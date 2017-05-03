package client

import (
	"golang.org/x/net/context"
	"github.com/docker/engine-api/client"
)

func (c *HTTPClient) IsContainerExist(container string) (exist bool, running bool, err error) {
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

