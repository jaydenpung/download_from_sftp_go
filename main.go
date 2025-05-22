package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/joho/godotenv"
	"github.com/pkg/sftp"
)

func main() {
	godotenv.Load(".env")
	var (
		sftpUser          = os.Getenv("SFTP_USER")
		sftpPass          = os.Getenv("SFTP_PASS")
		sftpHost          = os.Getenv("SFTP_HOST")
		sftpPort          = os.Getenv("SFTP_PORT")
		downloadDirectory = os.Getenv("DOWNLOAD_DIRECTORY")
		sourceDirectory = os.Getenv("SOURCE_DIRECTORY")
	)

	if sourceDirectory == "" {
		sourceDirectory = "."
	}

	// Create a url
	rawurl := fmt.Sprintf("sftp://%v:%v@%v", sftpUser, sftpPass, sftpHost)

	// Parse the URL
	parsedUrl, err := url.Parse(rawurl)
	if err != nil {
		log.Fatalf("Failed to parse SFTP To Go URL: %s", err)
	}

	// Get user name and pass
	user := parsedUrl.User.Username()
	pass, _ := parsedUrl.User.Password()

	// Parse Host and Port
	host := parsedUrl.Host

	// Get hostkey
	hostKey := getHostKey(host)

	log.Printf("Connecting to %s ...\n", host)

	var auths []ssh.AuthMethod

	// Try to use $SSH_AUTH_SOCK which contains the path of the unix file socket that the sshd agent uses
	// for communication with other processes.
	if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
	}

	// Use password authentication if provided
	if pass != "" {
		auths = append(auths, ssh.Password(pass))
	}

	// Initialize client configuration
	config := ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%s", host, sftpPort)

	// Connect to server
	conn, err := ssh.Dial("tcp", addr, &config)
	if err != nil {
		log.Fatalf("Failed to connect to host [%s]: %v", addr, err)
	}

	defer conn.Close()

	// Create new SFTP client
	sc, err := sftp.NewClient(conn)
	if err != nil {
		log.Fatalf("Unable to start SFTP subsystem: %v", err)
	}
	defer sc.Close()

	log.Printf("Connected to host!")

	// List files in the root directory .
	theFiles, err := listFiles(*sc, sourceDirectory)
	if err != nil {
		log.Fatalf("failed to list files in .: %v", err)
	}

	log.Printf("Found Files in . Files")
	// Output each file name and size in bytes
	log.Printf("%19s %12s %s", "MOD TIME", "SIZE", "NAME")
	for _, theFile := range theFiles[len(theFiles)-5:] {
		log.Printf("%19s %12s %s", theFile.ModTime, theFile.Size, theFile.Name)
		err = downloadFile(*sc, sourceDirectory+"/"+theFile.Name, downloadDirectory+"/"+theFile.Name)
		if err != nil {
			log.Fatal("Error downloading file: ", err)
		}
	}
}

type remoteFiles struct {
	Name    string
	Size    string
	ModTime string
}

func listFiles(sc sftp.Client, remoteDir string) (theFiles []remoteFiles, err error) {

	files, err := sc.ReadDir(remoteDir)
	if err != nil {
		return theFiles, fmt.Errorf("Unable to list remote dir: %v", err)
	}

	for _, f := range files {
		var name, modTime, size string

		name = f.Name()
		modTime = f.ModTime().Format("2006-01-02 15:04:05")
		size = fmt.Sprintf("%12d", f.Size())

		if f.IsDir() {
			name = name + "/"
			modTime = ""
			size = "PRE"
		}

		theFiles = append(theFiles, remoteFiles{
			Name:    name,
			Size:    size,
			ModTime: modTime,
		})
	}

	return theFiles, nil
}

// Upload file to sftp server
func uploadFile(sc sftp.Client, localFile, remoteFile string) (err error) {
	log.Printf("Uploading [%s] to [%s] ...", localFile, remoteFile)

	srcFile, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("Unable to open local file: %v", err)
	}
	defer srcFile.Close()

	// Make remote directories recursion
	parent := filepath.Dir(remoteFile)
	path := string(filepath.Separator)
	dirs := strings.Split(parent, path)
	for _, dir := range dirs {
		path = filepath.Join(path, dir)
		sc.Mkdir(path)
	}

	// Note: SFTP Go doesn't support O_RDWR mode
	dstFile, err := sc.OpenFile(remoteFile, (os.O_WRONLY | os.O_CREATE | os.O_TRUNC))
	if err != nil {
		return fmt.Errorf("Unable to open remote file: %v", err)
	}
	defer dstFile.Close()

	bytes, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("Unable to upload local file: %v", err)
	}
	log.Printf("%d bytes copied", bytes)

	return nil
}

// Download file from sftp server
func downloadFile(sc sftp.Client, remoteFile, localFile string) (err error) {

	log.Printf("Downloading [%s] to [%s] ...\n", remoteFile, localFile)
	// Note: SFTP To Go doesn't support O_RDWR mode
	srcFile, err := sc.OpenFile(remoteFile, (os.O_RDONLY))
	if err != nil {
		return fmt.Errorf("unable to open remote file: %v", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("unable to open local file: %v", err)
	}
	defer dstFile.Close()

	bytes, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("unable to download remote file: %v", err)
	}
	log.Printf("%d bytes copied to %v", bytes, dstFile)

	return nil
}

// Get host key from local known hosts
func getHostKey(host string) ssh.PublicKey {
	// parse OpenSSH known_hosts file
	// ssh or use ssh-keyscan to get initial key
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read known_hosts file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing %q: %v\n", fields[2], err)
				os.Exit(1)
			}
			break
		}
	}

	if hostKey == nil {
		fmt.Fprintf(os.Stderr, "No hostkey found for %s", host)
		os.Exit(1)
	}

	return hostKey
}
