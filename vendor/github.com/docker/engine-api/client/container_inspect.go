package client

import (
	"encoding/json"
	"net/http"
	"errors"

	"github.com/docker/engine-api/types"
	"golang.org/x/net/context"
)


var ContainerNotFoundError = errors.New("container not foud")

// ContainerInspect returns the container information.
func (cli *Client) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	serverResp, err := cli.get(ctx, "/containers/"+containerID+"/json", nil, nil)
	if err != nil {
		if serverResp.statusCode == http.StatusNotFound {
			return types.ContainerJSON{}, ContainerNotFoundError
		}
		return types.ContainerJSON{}, err
	}

	var response types.ContainerJSON
	err = json.NewDecoder(serverResp.body).Decode(&response)
	ensureReaderClosed(serverResp)
	return response, err
}
