package client

import (
	"fmt"
	"io"
	"errors"

	"golang.org/x/net/context"
	"golang.org/x/crypto/ssh"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/promise"
	"github.com/docker/engine-api/types"
)

func (c *HTTPClient) CmdExec(containerId string, channel ssh.Channel, cmd []string, setTty bool) error {
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
		return HoldHijackedConnection(execConfig.Tty, in, out, stderr, resp)
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

func getExecExitCode(c *HTTPClient, execID string) (bool, int, error) {
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
