package scp

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	"os"
)

type ContainerPipe struct {
	containerId string
	pipeReader  *io.PipeReader
	pipeWriter  *io.PipeWriter
	tarReader   *tar.Reader
	tarWriter   *tar.Writer
}

func sendE(channel ssh.Channel) error {
	// send "E\n" to client means this level directory is over
	wn, err := channel.Write([]byte{69, 10})
	if err == io.EOF {
		return errors.New("Client closed when write receiveSend E")
	}
	if err != nil {
		logrus.Errorln("Write receiveSend E error:", err)
		return err
	}
	if wn != 2 {
		errMsg := fmt.Sprintf("Broken pipe: write number [%d] not correctly when write receiveSend E, expect [%d]",
			wn, 2)
		logrus.Errorf(errMsg)
		return errors.New(errMsg)
	}

	// wait for response
	if ok, err := receiveResponse(channel); !ok {
		logrus.Errorln("ReceiveSendFile E response is not correct, error:", err)
		return err
	}
	return nil
}

func receiveSendFile(channel ssh.Channel, tarReader *tar.Reader) error {
	sendEPathNum := 0
	lastPath := ""
	thisPath := ""
	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			for i := 0; i < sendEPathNum; i++ {
				// send directory end "E\n" to channel
				err := sendE(channel)
				if err != nil {
					logrus.Errorln("Send E error when range pathList with io.EOF:", err)
					return err
				}
			}
			break
		}
		if err != nil {
			logrus.Debugln("we got error when do receiveSendFile:", err)
			return err
		}
		logrus.Debugf("Catch file Name: %s, Mode: %o, Size: %d, Type: %s\n", hdr.Name,
			hdr.FileInfo().Mode().Perm(), hdr.Size, string(hdr.Typeflag))

		// determine path change or not
		hdr.Name = strings.TrimSuffix(hdr.Name, "/")
		fNames := strings.Split(hdr.Name, "/")
		if hdr.FileInfo().IsDir() {
			thisPath = strings.Join(fNames, "/")
		} else {
			thisPath = strings.Join(fNames[:len(fNames)-1], "/")
		}

		if lastPath != "" && !strings.HasPrefix(thisPath, lastPath) {
			// is thisPath prefix != lastPath, means path change
			err := sendE(channel)
			if err != nil {
				logrus.Errorln("Send E error when path change:", err)
				return err
			}
			// when one directory sendE, sendEPathNum --
			sendEPathNum--
		}
		lastPath = thisPath

		var scpFileDesc string
		if hdr.FileInfo().IsDir() {
			// is directory
			scpFileDesc = fmt.Sprintf("D0%o %d %s\n", hdr.FileInfo().Mode().Perm(), hdr.Size, fNames[len(fNames)-1])
		} else {
			// is regular file
			// TODO: when file is link
			scpFileDesc = fmt.Sprintf("C0%o %d %s\n", hdr.FileInfo().Mode().Perm(), hdr.Size, fNames[len(fNames)-1])
		}

		// send file description to client
		logrus.Debugln("Send file description:", scpFileDesc)
		wn, err := channel.Write([]byte(scpFileDesc))
		if err == io.EOF {
			return errors.New("Client closed when write receiveSend file desc")
		}
		if err != nil {
			logrus.Errorln("Write receiveSend file desc error:", err)
			return err
		}
		if wn != len([]byte(scpFileDesc)) {
			errMsg := fmt.Sprintf("Broken pipe: write number [%d] not correctly when write receiveSend file desc, expect [%d]",
				wn, len([]byte(scpFileDesc)))
			logrus.Errorf(errMsg)
			return errors.New(errMsg)
		}

		// wait for response
		if ok, err := receiveResponse(channel); !ok {
			logrus.Errorln("ReceiveSendFile file desc response is not correct, error:", err)
			return err
		}

		// continue send file content
		if _, err := io.Copy(channel, tarReader); err != nil {
			logrus.Errorln("io copy tarReader to channel failed, error:", err)
			return err
		}

		if !hdr.FileInfo().IsDir() {
			// send byte(0) means file content ends
			wn, err := channel.Write([]byte{0})
			if err == io.EOF {
				return errors.New("Client closed when write receiveSend content desc")
			}
			if err != nil {
				logrus.Errorln("Write receiveSend file content error:", err)
				return err
			}
			if wn != 1 {
				errMsg := fmt.Sprintf("Broken pipe: write number [%d] not correctly when write receiveSend file content, expect [%d]",
					wn, 1)
				logrus.Errorf(errMsg)
				return errors.New(errMsg)
			}

			// wait for response
			if ok, err := receiveResponse(channel); !ok {
				logrus.Errorln("ReceiveSendFile file content response is not correct, error:", err)
				return err
			}
		} else {
			// when is directory, use sendEPathNum store path without send "E\n"
			sendEPathNum++
		}
	}
	return nil
}

func receiveResponse(channel ssh.Channel) (bool, error) {
	buf := make([]byte, 100)
	nr, err := channel.Read(buf)
	if err == io.EOF {
		// read over
		return false, errors.New("Channel closed when read response")
	}
	if err != nil {
		// error occurs
		logrus.Errorln("channel read error", err)
		return false, err
	}

	if nr == 1 {
		switch buf[nr-1] {
		case byte(0): // noremal response
			return true, nil
		case byte(1): // warning response
			logrus.Warningf(fmt.Sprintf("Get warning response: %d", buf[nr-1]))
			return true, nil
		case byte(2): // error response
			// do retry?
			return false, errors.New(fmt.Sprintf("Get error response: %d", buf[nr-1]))
		default: // unknown reponse
			return false, errors.New(fmt.Sprintf("Get unknown response: %d", buf[nr-1]))
		}
	}
	logrus.Errorln("Unknown response got:", buf[:nr])
	return false, errors.New("Unknown response got")
}

// ScpCopyFromContainer only support one container
func ScpCopyFromContainer(container string, srcPath string, channel ssh.Channel, c client.APIClient, isCopyPath bool) error {

	// TODO: if the file exist or not
	// scp: para1: not a regular file
	//srcStat, err := c.StatContainerPath(container, srcPath)
	//if err != nil {
	//	return err
	//}

	// client return response, begin send data
	content, _, err := c.CopyFromContainer(context.Background(), container, srcPath)
	if err != nil {
		return err
	}
	defer content.Close()

	// Open the tar archive for reading.
	tr := tar.NewReader(content)

	if ok, err := receiveResponse(channel); !ok {
		logrus.Errorln("ScpCopyFromContainer first response is not correct, error:", err)
		return err
	}

	// start scp communication
	if err := receiveSendFile(channel, tr); err != nil {
		logrus.Errorln("ReceiveSendFile error:", err)
		return err
	}

	return nil
}

func transferFile(channel ssh.Channel, containerPipes []*ContainerPipe) error {
	// send byte(0) for start
	_, err := channel.Write([]byte{0})
	if err != nil {
		logrus.Errorln("When do response of start transfer error:", err)
		return err
	}

	var (
		filePaths = []string{}
		tarType   = tar.TypeDir
	)
	buf := make([]byte, 32*1024)
	for {
		nr, err := channel.Read(buf)
		if err == io.EOF {
			// read over
			return nil
		}
		if err != nil {
			// error occurs
			logrus.Errorln("channel read error", err)
			return err
		}

		// file header description
		if (buf[0] == byte(68) || buf[0] == byte(67)) && buf[nr-1] == byte(10) {
			// "C0777 12 testfile" file description is over
			switch buf[0] {
			case byte(68): // "D", directory
				tarType = tar.TypeDir
			case byte(67): // "C", file
				tarType = tar.TypeReg
			default:
				return errors.New("Unknown file description:" + string(buf[:nr]))
			}

			scpFileDesc := strings.Split(string(buf[1:nr-1]), " ")
			if len(scpFileDesc) != 3 {
				// means maybe not file header goto to the file content
				logrus.Debugln("scpFileDesc length is not 3:", scpFileDesc)
				goto CONTENT
			}

			var fSrcName string = scpFileDesc[2]
			var fMode, fSize int64

			if fMode, err = strconv.ParseInt(scpFileDesc[0], 8, 64); err != nil {
				logrus.Debugln("scpFileDesc[0] cannot convert to int:", scpFileDesc[0])
				// goto to file content
				goto CONTENT
			}

			if fSize, err = strconv.ParseInt(scpFileDesc[1], 10, 64); err != nil {
				logrus.Debugln("scpFileDesc[1] cannot convert to int:", scpFileDesc[1])
				// goto to file content
				goto CONTENT
			}

			// transfer file description
			hdr := &tar.Header{
				Name:       strings.Join(append(filePaths, fSrcName), "/"),
				Typeflag:   byte(tarType),
				Mode:       fMode,
				Size:       fSize,
				ModTime:    time.Now(),
				AccessTime: time.Now(),
				ChangeTime: time.Now(),
			}

			// write tar header with path
			for _, containerPipe := range containerPipes {
				if err := containerPipe.tarWriter.WriteHeader(hdr); err != nil {
					logrus.Errorln("write tar file header failed", err)
					return err
				}
			}

			if tarType == tar.TypeDir {
				filePaths = append(filePaths, fSrcName)
			}

			// send byte(0) for response
			_, err := channel.Write([]byte{0})
			if err != nil {
				logrus.Errorln("When do response of receive file description error:", err)
				return err
			}
			continue
		} else if len(buf[:nr]) == 2 && buf[0] == byte(69) && buf[1] == byte(10) {
			// "E\n" directory ends remove the last path
			filePaths = filePaths[:len(filePaths)-1]

			// send byte(0) for response
			_, err := channel.Write([]byte{0})
			if err != nil {
				logrus.Errorln("When do response of receive path ends error:", err)
				return err
			}
			continue
		}
	CONTENT:
		contentBuf := buf[:nr]
		if (buf[nr-1]) == byte(0) {
			// file content ends
			contentBuf = buf[:nr-1]
		}

		// file content read/write
		for _, containerPipe := range containerPipes {
			if _, err := containerPipe.tarWriter.Write(contentBuf); err != nil {
				logrus.Errorln("tar writer write file content error", err)
				return err
			}
		}

		// file content ends
		if (buf[nr-1]) == byte(0) {
			// send byte(0) for response
			_, err := channel.Write([]byte{0})
			if err != nil {
				logrus.Errorln("When do response of receive file ends error:", err)
				return err
			}
		}
	}

}

// ScpCopyToContainer support copy to multi-containers
func ScpCopyToContainer(containers []string, dstPath string, channel ssh.Channel, c client.APIClient) error {
	var containerPipes = []*ContainerPipe{}
	for _, container := range containers {
		// init pipe to change raw file content to tar format
		pr, pw := io.Pipe()
		tw := tar.NewWriter(pw)
		containerPipes = append(containerPipes, &ContainerPipe{
			containerId: container,
			pipeReader:  pr,
			pipeWriter:  pw,
			tarWriter:   tw,
		})
	}

	transFileChan := make(chan error, 1)
	go func() {
		err := transferFile(channel, containerPipes)
		transFileChan <- err
	}()

	var wg sync.WaitGroup
	achieveChan := make(chan error, 1)
	for _, containerPipe := range containerPipes {
		go func(cPipe *ContainerPipe) {
			wg.Add(1)
			defer wg.Done()
			options := types.CopyToContainerOptions{
				ContainerID:               cPipe.containerId,
				Path:                      dstPath,
				Content:                   cPipe.pipeReader,
				AllowOverwriteDirWithFile: false,
			}
			if err := c.CopyToContainer(context.Background(), options); err != nil {
				achieveChan <- err
			}
			logrus.Debugln("Copy to container achieve api end:", cPipe.containerId)
		}(containerPipe)
	}

	select {
	case err := <-transFileChan:
		// close pipes
		for _, containerPipe := range containerPipes {
			containerPipe.tarWriter.Close()
			containerPipe.pipeWriter.Close()
		}

		if err != nil {
			logrus.Errorln("Transfer file to container error", err)
			return err
		}
	case err := <-achieveChan:
		// close pipes
		for _, containerPipe := range containerPipes {
			containerPipe.tarWriter.Close()
			containerPipe.pipeWriter.Close()
		}

		if err != nil {
			logrus.Errorln("Docker achieve file transfer to container error", err)
			return err
		}
	}
	wg.Wait()
	return nil
}

func splitPathDirEntry(path string) (dir, base string) {
	cleanedPath := filepath.Clean(filepath.ToSlash(path))

	if filepath.Base(path) == "." {
		cleanedPath += string(filepath.Separator) + "."
	}

	return filepath.Dir(cleanedPath), filepath.Base(cleanedPath)
}

func CopyFileToContainer(c client.APIClient, tarContent io.Reader, dstContainer, dstPath string) (err error) {

	// Prepare destination copy info by stat-ing the container path.
	dstStat, err := c.ContainerStatPath(context.Background(), dstContainer, dstPath)

	// If the destination is a symbolic link, we should evaluate it.
	if err == nil && dstStat.Mode&os.ModeSymlink != 0 {
		linkTarget := dstStat.LinkTarget
		if !filepath.IsAbs(linkTarget) {
			// Join with the parent directory.
			dstParent, _ := splitPathDirEntry(dstPath)
			linkTarget = filepath.Join(dstParent, linkTarget)
		}

		dstPath = linkTarget
		dstStat, err = c.ContainerStatPath(context.Background(), dstContainer, linkTarget)
	}

	dstParent, _ := splitPathDirEntry(dstPath)
	options := types.CopyToContainerOptions{
		ContainerID:               dstContainer,
		Path:                      dstParent,
		Content:                   tarContent,
		AllowOverwriteDirWithFile: false,
	}

	return c.CopyToContainer(context.Background(), options)
}
