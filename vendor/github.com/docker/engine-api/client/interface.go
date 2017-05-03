package client

import (
	"io"

	"golang.org/x/net/context"
	"github.com/docker/engine-api/types"
)

// APIClient is an interface that clients that talk with a docker server must implement.
type APIClient interface {
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)

	ContainerExecAttach(ctx context.Context, execID string, config types.ExecConfig) (types.HijackedResponse, error)
	ContainerExecCreate(ctx context.Context, container string, config types.ExecConfig) (types.ContainerExecCreateResponse, error)
	ContainerExecInspect(ctx context.Context, execID string) (types.ContainerExecInspect, error)
	ContainerExecResize(ctx context.Context, execID string, options types.ResizeOptions) error
	ContainerExecStart(ctx context.Context, execID string, config types.ExecStartCheck) error

	ContainerStatPath(ctx context.Context, containerID, path string) (types.ContainerPathStat, error)
	CopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, types.ContainerPathStat, error)
	CopyToContainer(ctx context.Context, options types.CopyToContainerOptions) error
}

// Ensure that Client always implements APIClient.
var _ APIClient = &Client{}
