package ssh

import (
	"net"
	"fmt"
	"sync"
	"strings"
	"encoding/binary"

	"golang.org/x/crypto/ssh"
	"github.com/Sirupsen/logrus"

	"github.com/zanecloud/tunneld/tunnel/scp"
//	"github.com/zanecloud/tunneld/tunnel/client"
	"github.com/docker/engine-api/client"
	"context"
	"github.com/docker/engine-api/types"
	"errors"
	"io"
	"github.com/docker/docker/pkg/promise"
	"github.com/docker/docker/pkg/stdcopy"
)

var (
	SSHConfig *ssh.ServerConfig
	DEFAULT_SHELL string = "sh"
)

func init() {
	SSHConfig = &ssh.ServerConfig{
		// Remove to disable password auth.
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Authorize use and container is valid here
			return nil, nil
		},
	}

	private, err := ssh.ParsePrivateKey([]byte(id_rsa))
	if err != nil {
		logrus.Fatal("Failed to parse private key: ", err)
	}

	SSHConfig.AddHostKey(private)
}

func HandleSSHConnection(nConn net.Conn, c client.APIClient, isNoSshAuth bool) error {
	if isNoSshAuth {
		SSHConfig.NoClientAuth = true
	}

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	sshConn, chans, _, err := ssh.NewServerConn(nConn, SSHConfig)
	if err != nil {
		logrus.Errorln("failed to handshake: ", err)
		return err
	}

	logrus.Infof("new ssh connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	// Service the incoming Channel channel.
	go handleChannels(sshConn, chans, c)

	return nil
}


func isContainerExist(c client.APIClient , container string) (exist bool, running bool, err error) {
	cInfo, err := c.ContainerInspect(context.Background(), container)
	if err == client.ContainerNotFoundError {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if !cInfo.State.Running {
		// not running
		return true, false, nil
	}
	return true, true, nil
}



func handleChannels(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel, c client.APIClient) {
	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			logrus.Errorf("could not accept channel (%s)", err)
			continue
		}

		// verify containers and permission
		notExistContainers := []string{}
		notRunningContainers := []string{}
		errorContainers := []string{}
		for _, container := range strings.Split(sshConn.User(), ",") {
			exist, running, err := isContainerExist(c,container)
			if err != nil {
				errorContainers = append(errorContainers, container)
			} else {
				if !exist {
					notExistContainers = append(notExistContainers, container)
				} else {
					if !running {
						notRunningContainers = append(notRunningContainers, container)
					}
				}
			}
		}
		if len(notRunningContainers) > 0 || len(notExistContainers) > 0 || len(errorContainers) > 0 {
			logrus.Debugf("Container not running %v, not exist %v, error %v",
				notRunningContainers, notExistContainers, errorContainers)
			if len(notRunningContainers) > 0 {
				fmt.Fprintln(channel, "Container Not Running:", notRunningContainers)
			}
			if len(notExistContainers) > 0 {
				fmt.Fprintln(channel, "Container Not Exist:", notExistContainers)
			}
			if len(errorContainers) > 0 {
				fmt.Fprintln(channel, "Container Error:", errorContainers)
			}
			channel.Close()
			logrus.Debugln("Session closed with container errors")
		} else {
			// start ssh session for containers
			containers := strings.Split(sshConn.User(), ",")
			if len(containers) == 0 {
				fmt.Fprintln(channel, "No Contaienr Input")
				channel.Close()
				return
			} else {
				go startSSHSession(containers, channel, requests, c)
			}
		}
	}
}

func startSSHSession(containers []string, channel ssh.Channel, in <-chan *ssh.Request, c client.APIClient) {
	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	for req := range in {
		logrus.Debugf("%v %s", req.Payload, req.Payload)
		ok := false
		switch req.Type {
		case "exec":
			ok = true
			command := []string{DEFAULT_SHELL, "-c", string(req.Payload[4 : req.Payload[3]+4])}
			commandSplits := strings.Split(command[2], " ")
			if commandSplits[0] == "scp" {
				// do scp
				var (
					isCopyPath = false
					isCopyTo = false
					isCopyFrom =false
				)
				for _, cs := range commandSplits {
					if cs == "-r" {
						// copy path
						isCopyPath = true
					}
					if cs == "-f" {
						isCopyFrom = true
					}
					if cs == "-t" {
						isCopyTo = true
					}
				}
				if isCopyTo == isCopyFrom {
					logrus.Errorln("Unknown scp operation found, return, command:", command)
					goto CLOSE
				}

				targetPath := commandSplits[len(commandSplits)-1]
				if isCopyTo {
					err := scp.ScpCopyToContainer(containers, targetPath, channel, c)
					if err != nil {
						logrus.Errorln("failed to scp copy file to container, error:", err)
						fmt.Fprintln(channel, "Error:", err)
						goto CLOSE
					}
				}
				if isCopyFrom {
					// when containers input, we only use first container to copy from
					err := scp.ScpCopyFromContainer(containers[0], targetPath, channel, c, isCopyPath)
					if err != nil {
						logrus.Errorf("failed to scp copy file from container [%s], error: %v",
							containers[0], err)
						fmt.Fprintln(channel, "Error:", err)
						goto CLOSE
					}
				}

			} else {
				// do exec
				for _, container := range containers {
					logrus.Debugf("start exec session with container %s, command: %s",
						container, command)

					fmt.Fprintf(channel, "[Container: %s]\n", container)
					err := cmdExec(c,container, channel, command, false)
					if err != nil {
						logrus.Errorf("failed to exit bash (%v) of container %s\n", err, container)
						fmt.Fprintln(channel, "Error:", err)
					}
					fmt.Fprintln(channel, "")
				}
			}
			CLOSE:
			channel.Close()
			logrus.Debugln("exec session closed")
		case "shell":
			container := containers[0]
			logrus.Debugln("start shell session for container:", container)

			// Teardown session
			var once sync.Once
			close := func() {
				channel.Close()
				logrus.Debugln("shell session closed for container:", container)
			}

			// Pipe session to bash and visa-versa
			go func() {
				// do call docker exec, io.Copy
				cmdExec(c , container, channel, []string{DEFAULT_SHELL}, true)
				//io.Copy(channel, f)
				once.Do(close)
			}()

			// We don't accept any commands (Payload),
			// only the default shell.
			if len(req.Payload) == 0 {
				ok = true
			}
		case "pty-req":
			logrus.Debugln("start pty-req session")
			// Responding 'ok' here will let the client
			// know we have a pty ready for input
			ok = true
			// Parse body...
			termLen := req.Payload[3]
			termEnv := string(req.Payload[4 : termLen+4])
			w, h := parseDims(req.Payload[termLen+4:])
			//SetWinsize(f.Fd(), w, h)
			logrus.Println(w)
			logrus.Println(h)
			logrus.Printf("pty-req '%s'", termEnv)
		//case "window-change":
		//	log.Println("this is window-change")
		//	w, h := parseDims(req.Payload)
		//	SetWinsize(f.Fd(), w, h)
		//	continue //no response
		}

		if !ok {
			logrus.Printf("declining %s request...", req.Type)
		}

		req.Reply(ok, nil)
	}
}

// parseDims extracts two uint32s from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}



func  cmdExec(c client.APIClient, containerId string, channel ssh.Channel, cmd []string, setTty bool) error {
	execConfig := &types.ExecConfig{
		Container:  containerId,
		Cmd:        cmd,
		Tty:        setTty,
		AttachStdin: true,
		AttachStdout: true,
		AttachStderr: true,
	}

	response, err := c.ContainerExecCreate(context.Background(), containerId, *execConfig)
	if err != nil {
		return err
	}

	execID := response.ID
	if execID == "" {
		fmt.Fprintf(channel, "exec ID empty")
		return errors.New("exec ID empty")
	}

	// Interactive exec requested.
	var (
		out, stderr io.Writer
		in          io.ReadCloser
		errCh       chan error
	)

	if execConfig.AttachStdin {
		in = channel
	}
	if execConfig.AttachStdout {
		out = channel
	}
	if execConfig.AttachStderr {
		if execConfig.Tty {
			stderr = channel
		} else {
			stderr = channel
		}
	}

	resp, err := c.ContainerExecAttach(context.Background(), execID, *execConfig)
	if err != nil {
		return err
	}
	defer resp.Close()
	//if in != nil && execConfig.Tty {
	//	if err := cli.setRawTerminal(); err != nil {
	//		return err
	//	}
	//	defer cli.restoreTerminal(in)
	//}
	errCh = promise.Go(func() error {
		return holdHijackedConnection(execConfig.Tty, in, out, stderr, resp)
	})

	//if execConfig.Tty && cli.isTerminalIn {
	//	if err := cli.monitorTtySize(execID, true); err != nil {
	//		fmt.Fprintf(cli.err, "Error monitoring TTY size: %s\n", err)
	//	}
	//}

	if err := <-errCh; err != nil {
		logrus.Debugf("Error hijack: %s", err)
		return err
	}

	var status int
	if _, status, err = getExecExitCode(c, execID); err != nil {
		return err
	}

	if status != 0 {
		return errors.New("status == 0 error")
	}

	return nil
}

func getExecExitCode(c client.APIClient, execID string) (bool, int, error) {
	var ErrConnectionFailed = errors.New("Cannot connect to the Docker daemon. Is the docker daemon running on this host?")

	resp, err := c.ContainerExecInspect(context.Background(), execID)
	if err != nil {
		// If we can't connect, then the daemon probably died.
		if err != ErrConnectionFailed {
			return false, -1, err
		}
		return false, -1, nil
	}

	return resp.Running, resp.ExitCode, nil
}
func holdHijackedConnection(tty bool, inputStream io.ReadCloser, outputStream, errorStream io.Writer, resp types.HijackedResponse) error {
	var err error
	receiveStdout := make(chan error, 1)
	if outputStream != nil || errorStream != nil {
		go func() {
			// When TTY is ON, use regular copy
			if tty && outputStream != nil {
				_, err = io.Copy(outputStream, resp.Reader)
			} else {
				_, err = stdcopy.StdCopy(outputStream, errorStream, resp.Reader)
			}
			logrus.Debugf("[hijack] End of stdout")
			receiveStdout <- err
		}()
	}

	stdinDone := make(chan struct{})
	go func() {
		if inputStream != nil {
			io.Copy(resp.Conn, inputStream)
			logrus.Debugf("[hijack] End of stdin")
		}

		if err := resp.CloseWrite(); err != nil {
			logrus.Debugf("Couldn't send EOF: %s", err)
		}
		close(stdinDone)
	}()

	select {
	case err := <-receiveStdout:
		if err != nil {
			logrus.Debugf("Error receiveStdout: %s", err)
			return err
		}
	case <-stdinDone:
		if outputStream != nil || errorStream != nil {
			if err := <-receiveStdout; err != nil {
				logrus.Debugf("Error receiveStdout: %s", err)
				return err
			}
		}
	}

	return nil
}
