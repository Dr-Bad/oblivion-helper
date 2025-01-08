// Copyright (C) 2024 ShadowZagrosDev
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	pb "oblivion-helper/gRPC"

	box "github.com/sagernet/sing-box"
	option "github.com/sagernet/sing-box/option"

	"atomicgo.dev/isadmin"
	"github.com/fatih/color"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Constants for server setup and configuration
const (
	protocolType            = "tcp"               // Connection protocol used by the server
	serverAddress           = "127.0.0.1:50051"   // Localhost address for gRPC server
	configFileName          = "sbConfig.json"     // Name of the sing-box configuration file
	exportListFileName      = "sbExportList.json" // Name of the export list config file
	statusChannelCap        = 100                 // Capacity of the status channel
	gracefulShutdownTimeout = 2 * time.Second     // Timeout for graceful shutdown
	rulesetFolderName       = "ruleset"           // Name of the folder to store rulesets
	macDnsServer            = "172.19.0.2"        // DNS server to use on macOS for tun mode
)

// Global variable for version
var Version = "dev"

// Logger wraps multiple loggers with different levels (info, warn, error, fatal)
type Logger struct {
	info, warn, error, fatal *log.Logger
}

// NewLogger initializes a Logger instance with colored prefixes
func NewLogger() *Logger {
	return &Logger{
		info:  log.New(os.Stdout, color.GreenString("[INFO] "), log.Ldate|log.Ltime|log.Lmsgprefix),
		warn:  log.New(os.Stdout, color.YellowString("[WARN] "), log.Ldate|log.Ltime|log.Lmsgprefix),
		error: log.New(os.Stderr, color.RedString("[ERROR] "), log.Ldate|log.Ltime|log.Lmsgprefix),
		fatal: log.New(os.Stderr, color.New(color.FgRed, color.Bold).Sprint("[FATAL] "), log.Ldate|log.Ltime|log.Lmsgprefix),
	}
}

// Server is the main gRPC server implementation
type Server struct {
	pb.UnimplementedOblivionServiceServer
	mu           sync.RWMutex   // Synchronizes access to server state
	statusChange chan string    // Channel to broadcast status updates
	dirPath      string         // Directory path of the executable
	instance     *box.Box       // Sing-box instance
	logger       *Logger        // Logger for server messages
	exportConfig ExportConfig   // Export config
	macDNS       *MacDNSManager // Manages macOS DNS settings
}

// ExportConfig holds the structure for the export config file
type ExportConfig struct {
	Interval int               `json:"interval"` // Interval in days for ruleset update checks
	URLs     map[string]string `json:"urls"`     // URLs for downloading rulesets
}

// MacDNSManager manages DNS settings on macOS
type MacDNSManager struct {
	originalDNS map[string][]string // Stores original DNS settings for each network service
	logger      *Logger             // Logger for MacDNSManager
}

// NewMacDNSManager creates a new MacDNSManager
func NewMacDNSManager(logger *Logger) *MacDNSManager {
	return &MacDNSManager{
		originalDNS: make(map[string][]string),
		logger:      logger,
	}
}

// NewServer creates and initializes a new Server instance
func NewServer(logger *Logger) (*Server, error) {
	execDir, err := getExecutableDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable directory: %w", err)
	}

	macDNSManager := NewMacDNSManager(logger)

	return &Server{
		statusChange: make(chan string, statusChannelCap),
		dirPath:      execDir,
		logger:       logger,
		macDNS:       macDNSManager,
	}, nil
}

// getExecutableDir returns the directory of the current executable
func getExecutableDir() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	return filepath.Dir(executable), nil
}

// loadSingBoxConfig loads and parses the Sing-Box configuration file.
func (s *Server) loadSingBoxConfig() (*option.Options, error) {
	configPath := filepath.Join(s.dirPath, configFileName)

	_, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		return nil, status.Errorf(codes.NotFound, "sing-box config not found at %s", configPath)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read sing-box config: %v", err)
	}

	var options option.Options
	if err := json.Unmarshal(content, &options); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse sing-box config: %v", err)
	}

	return &options, nil
}

// loadExportConfig loads and parses the export config file
func (s *Server) loadExportConfig() error {
	configPath := filepath.Join(s.dirPath, exportListFileName)

	s.exportConfig.URLs = nil

	_, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		s.logger.warn.Printf("Export config not found at %s, skipping...", configPath)
		return nil // Skip if the config doesn't exist
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		s.logger.error.Printf("Failed to read export config: %v", err)
		return fmt.Errorf("failed to read export config: %w", err)
	}

	if len(content) == 0 {
		s.logger.warn.Println("Export config is empty, skipping...")
		return nil
	}

	var config ExportConfig
	if err := json.Unmarshal(content, &config); err != nil {
		s.logger.error.Printf("Failed to parse export config: %v", err)
		return fmt.Errorf("failed to parse export config: %w", err)
	}

	if len(config.URLs) == 0 {
		s.logger.warn.Println("No URLs found in export config, skipping...")
		return nil
	}

	s.exportConfig = config
	return nil
}

// needsDownload checks if any ruleset needs to be downloaded based on the export config
func (s *Server) needsDownload() bool {
	if err := s.loadExportConfig(); err != nil {
		s.logger.error.Printf("Error loading export config: %v", err)
		return false
	}

	if len(s.exportConfig.URLs) == 0 {
		return false // No URLs to download, so no download needed
	}

	rulesetPath := filepath.Join(s.dirPath, rulesetFolderName)

	for filename := range s.exportConfig.URLs {
		filePath := filepath.Join(rulesetPath, filename)

		fileInfo, err := os.Stat(filePath)
		if os.IsNotExist(err) {
			return true // File does not exist, needs download
		} else if err != nil {
			s.logger.error.Printf("Error checking file %s: %v", filename, err)
			continue // Error checking file, skip to next
		}

		if s.exportConfig.Interval <= 0 {
			continue // Invalid interval, skip to next file
		}

		if time.Since(fileInfo.ModTime()) > time.Duration(s.exportConfig.Interval)*24*time.Hour {
			return true // File is older than the interval, needs download
		}
	}

	return false // All files are up to date
}

// downloadRulesets manages the downloading of rulesets based on the export config
func (s *Server) downloadRulesets() error {
	// Check if any download is needed before proceeding
	if !s.needsDownload() {
		return nil // No download needed
	}

	s.broadcastStatus("preparing")

	if err := s.loadExportConfig(); err != nil {
		return fmt.Errorf("error loading export config: %w", err)
	}

	if len(s.exportConfig.URLs) == 0 {
		return nil // Nothing to download
	}

	rulesetPath := filepath.Join(s.dirPath, rulesetFolderName)

	if _, err := os.Stat(rulesetPath); os.IsNotExist(err) {
		if err := os.MkdirAll(rulesetPath, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create ruleset directory: %w", err)
		}
		s.logger.info.Printf("Created ruleset directory: %s", rulesetPath)
	}

	for filename, url := range s.exportConfig.URLs {
		filePath := filepath.Join(rulesetPath, filename)

		fileInfo, err := os.Stat(filePath)
		if os.IsNotExist(err) {
			if err := s.downloadFile(url, filePath); err != nil {
				s.logger.error.Printf("Error downloading file %s: %v", filename, err)
			} else {
				s.logger.info.Printf("Downloaded file %s from %s", filename, url)
			}
			continue
		} else if err != nil {
			s.logger.error.Printf("Error checking file %s: %v", filename, err)
			continue
		}

		if s.exportConfig.Interval <= 0 {
			s.logger.info.Printf("Skipping interval check for file %s due to invalid interval in config", filename)
			continue
		}

		if time.Since(fileInfo.ModTime()) > time.Duration(s.exportConfig.Interval)*24*time.Hour {
			if err := s.downloadFile(url, filePath); err != nil {
				s.logger.error.Printf("Error updating file %s: %v", filename, err)
			} else {
				s.logger.info.Printf("Updated file %s from %s", filename, url)
			}
		} else {
			s.logger.info.Printf("File %s is up to date", filename)
		}
	}
	return nil
}

// downloadFile downloads a file from a URL to a given path
func (s *Server) downloadFile(url, filePath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to get URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-200 status code: %d", resp.StatusCode)
	}

	out, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to copy response body: %w", err)
	}

	return nil
}

// getMacNetworkServices lists all network services using `networksetup -listallnetworkservices` in macOS
func (m *MacDNSManager) getMacNetworkServices() ([]string, error) {
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list network services: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	var services []string
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line != "" {
			services = append(services, line)
		}
	}
	return services, nil
}

// getDNSForService gets the DNS servers for a given service
func (m *MacDNSManager) getDNSForService(service string) ([]string, error) {
	cmd := exec.Command("networksetup", "-getdnsservers", service)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get dns servers for service %s: %w", service, err)
	}

	var dns []string
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "There aren't any DNS Servers set") {
			return []string{"empty"}, nil
		}
		if line != "" {
			dns = append(dns, line)
		}
	}
	return dns, nil
}

// setDNSForService sets the DNS servers for a given service
func (m *MacDNSManager) setDNSForService(service string, dns []string) error {
	args := append([]string{"-setdnsservers", service}, dns...)
	cmd := exec.Command("networksetup", args...)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to set dns for service %s: %w", service, err)
	}
	return nil
}

// applyCustomDNS applies the custom DNS settings (macDnsServer) to all network services on macOS
func (m *MacDNSManager) applyCustomDNS() error {
	services, err := m.getMacNetworkServices()
	if err != nil {
		return fmt.Errorf("error fetching network services: %w", err)
	}

	for _, service := range services {
		dns, err := m.getDNSForService(service)
		if err != nil {
			m.logger.warn.Printf("Error getting DNS for service %s: %v\n", service, err)
			continue
		}
		m.originalDNS[service] = dns

		// Explanation:
		// On macOS, when using a TUN interface (like sing-box's tun mode), DNS queries might leak
		// to the system's default DNS servers instead of being routed through the VPN/proxy.
		// To prevent these DNS leaks, we forcefully change the system's DNS settings to point
		// to our local DNS resolver (macDnsServer which is usually a local address like 172.19.0.2).
		// This ensures all DNS queries are routed through our controlled network interface.
		err = m.setDNSForService(service, []string{macDnsServer})
		if err != nil {
			m.logger.warn.Printf("Error setting DNS for service %s: %v\n", service, err)
		} else {
			m.logger.info.Printf("Set DNS for %s to %s\n", service, macDnsServer)
		}
	}
	return nil
}

// restoreOriginalDNS restores the original DNS settings for all network services on macOS
func (m *MacDNSManager) restoreOriginalDNS() error {
	for service, dns := range m.originalDNS {

		// Explanation:
		// When the program or the VPN/proxy is stopped, it's essential to restore the system's
		// DNS settings back to what they were before. This is done to prevent any lingering
		// issues or unexpected behavior with the network after the program is shut down.
		// We iterate through the stored original DNS settings and set them back for each
		// network service. If a service had no dns, then we set it to "empty" which means remove all DNS settings for it
		err := m.setDNSForService(service, dns)
		if err != nil {
			m.logger.warn.Printf("Error restoring DNS for service %s: %v\n", service, err)
		} else {
			m.logger.info.Printf("Restored DNS for %s to %v\n", service, dns)
		}
	}
	return nil
}

// startSingBox starts the Sing-Box process
func (s *Server) startSingBox() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.instance != nil {
		return status.Errorf(codes.AlreadyExists, "sing-box is already running")
	}

	if err := s.downloadRulesets(); err != nil {
		s.broadcastStatus("download-failed")
		return status.Errorf(codes.FailedPrecondition, "Failed to download rulesets: %v", err)
	}

	options, err := s.loadSingBoxConfig()
	if err != nil {
		return err
	}

	instance, err := box.New(box.Options{
		Options: *options,
		Context: context.Background(),
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create sing-box instance: %v", err)
	}

	if err := instance.Start(); err != nil {
		return status.Errorf(codes.Internal, "failed to start sing-box: %v", err)
	}

	if runtime.GOOS == "darwin" {
		if err := s.macDNS.applyCustomDNS(); err != nil {
			return status.Errorf(codes.Internal, "failed to apply custom dns settings %v", err)
		}
	}

	s.instance = instance
	s.broadcastStatus("started")
	s.logger.info.Println("Sing-box started")
	return nil
}

// stopSingBox stops the Sing-Box process
func (s *Server) stopSingBox() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.instance == nil {
		return status.Errorf(codes.FailedPrecondition, "sing-box is not running")
	}

	if err := s.instance.Close(); err != nil {
		return status.Errorf(codes.Internal, "failed to stop sing-box: %v", err)
	}

	if runtime.GOOS == "darwin" {
		if err := s.macDNS.restoreOriginalDNS(); err != nil {
			return status.Errorf(codes.Internal, "failed to restore original dns settings %v", err)
		}
	}

	s.instance = nil
	s.broadcastStatus("stopped")
	s.logger.info.Println("Sing-box stopped")
	return nil
}

// Start handles the gRPC Start request to initiate Sing-Box
func (s *Server) Start(ctx context.Context, req *pb.StartRequest) (*pb.StartResponse, error) {
	if err := s.startSingBox(); err != nil {
		s.logger.error.Printf("Start error: %v", err)
		return nil, err
	}
	return &pb.StartResponse{Message: "Sing-Box started successfully."}, nil
}

// Stop handles the gRPC Stop request to terminate Sing-Box
func (s *Server) Stop(ctx context.Context, req *pb.StopRequest) (*pb.StopResponse, error) {
	if err := s.stopSingBox(); err != nil {
		s.logger.error.Printf("Stop error: %v", err)
		return nil, err
	}
	return &pb.StopResponse{Message: "Sing-Box stopped successfully."}, nil
}

// Exit handles the gRPC Exit request to shut down the service gracefully
func (s *Server) Exit(ctx context.Context, req *pb.ExitRequest) (*pb.ExitResponse, error) {
	s.logger.info.Println("Exiting Oblivion-Helper...")

	if s.instance != nil {
		if err := s.stopSingBox(); err != nil {
			s.logger.error.Printf("Exit stop error: %v", err)
		}
	}

	go func() {
		time.Sleep(gracefulShutdownTimeout)
		os.Exit(0)
	}()

	return &pb.ExitResponse{}, nil
}

// StreamStatus streams the current status of Sing-Box to the client
func (s *Server) StreamStatus(req *pb.StatusRequest, stream pb.OblivionService_StreamStatusServer) error {
	var lastStatus string
	for {
		select {
		case <-stream.Context().Done(): // Handle client disconnection
			s.logger.warn.Println("Stream closed by client")
			if s.instance != nil {
				if err := s.stopSingBox(); err != nil {
					s.logger.error.Printf("Stream stop error: %v", err)
					return status.Errorf(codes.Aborted, "failed to stop service during stream closure: %v", err)
				}
			}
			return stream.Context().Err()

		case status, ok := <-s.statusChange: // Receive status updates
			if !ok {
				s.logger.warn.Println("Status channel closed")
				return nil // The status channel was closed
			}

			if status == lastStatus {
				continue
			}
			lastStatus = status

			if err := stream.Send(&pb.StatusResponse{Status: status}); err != nil {
				s.logger.error.Printf("Status stream error: %v", err)
				return err // Failed to send status update
			}
		}
	}
}

// broadcastStatus sends a status update to the status channel
func (s *Server) broadcastStatus(status string) {
	select {
	case s.statusChange <- status:
		// Successfully sent status update
	default:
		s.logger.warn.Println("Status channel full, dropping update")
	}
}

// main initializes the logger, checks admin privileges, creates the server, and starts the gRPC server
func main() {
	logger := NewLogger()
	handleCommandLineArgs(logger)

	if !isadmin.Check() {
		logger.fatal.Fatal("Oblivion-Helper must be run as an administrator/root.")
	}

	server, err := NewServer(logger)
	if err != nil {
		logger.fatal.Fatalf("Failed to create server: %v", err)
	}

	startGRPCServer(server, logger)
}

// handleCommandLineArgs processes command-line arguments like "version"
func handleCommandLineArgs(logger *Logger) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			logger.info.Printf("Oblivion-Helper Version: %s\n", Version)
			logger.info.Printf("Environment: %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		default:
			logger.warn.Printf("Unknown command '%s'.\nUse 'version' to display version information.\n", os.Args[1])
		}
		os.Exit(0)
	}
}

// startGRPCServer starts the gRPC server and handles termination signals
func startGRPCServer(server *Server, logger *Logger) {
	lis, err := net.Listen(protocolType, serverAddress)
	if err != nil {
		logger.fatal.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterOblivionServiceServer(grpcServer, server)

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.info.Printf("Server started on: %s", serverAddress)
		if err := grpcServer.Serve(lis); err != nil {
			logger.fatal.Fatalf("Failed to serve: %v", err)
		}
	}()

	<-shutdown
	logger.warn.Println("Received termination signal, shutting down...")

	if server.instance != nil {
		if err := server.stopSingBox(); err != nil {
			logger.error.Printf("Shutdown stop error: %v", err)
		}
	}

	close(server.statusChange)
	grpcServer.GracefulStop()

	logger.info.Println("Server terminated gracefully")
}
