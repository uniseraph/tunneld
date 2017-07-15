package client

import (
	"io"

	"github.com/docker/engine-api/types"
	"golang.org/x/net/context"
)

// APIClient is an interface that clients that talk with a docker server must implement.
type APIClient interface {
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)

	ContainerExecAttach(ctx context.Context, execID string, config types.ExecConfig) (types.HijackedResponse, error)
	ContainerExecCreate(ctx context.Context, container string, config types.ExecConfig) (types.ContainerExecCreateResponse, error)
	ContainerExecInspect(ctx context.Context, execID string) (types.ContainerExecInspect, error)
	ContainerExecStart(ctx context.Context, execID string, config types.ExecStartCheck) error
	ContainerResize(ctx context.Context, options types.ResizeOptions) error
	ContainerExecResize(ctx context.Context, options types.ResizeOptions) error

	ContainerStatPath(ctx context.Context, containerID, path string) (types.ContainerPathStat, error)
	CopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, types.ContainerPathStat, error)
	CopyToContainer(ctx context.Context, options types.CopyToContainerOptions) error
}

// Ensure that Client always implements APIClient.
var _ APIClient = &Client{}
