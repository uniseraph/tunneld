package client

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/net/context"
	"golang.org/x/crypto/ssh"

	"github.com/docker/engine-api/types"
)

type copyDirection int

const (
	fromContainer copyDirection = (1 << iota)
	toContainer
	acrossContainers = fromContainer | toContainer
)

func (c *HTTPClient) StatContainerPath(containerName, path string) (types.ContainerPathStat, error) {
	return c.ContainerStatPath(context.Background(), containerName, path)
}

func (c *HTTPClient) CopyFileFromContainer(channel ssh.Channel, srcContainer, srcPath string) (err error) {
	content, _, err := c.CopyFromContainer(context.Background(), srcContainer, srcPath)
	if err != nil {
		return err
	}
	defer content.Close()

	// See comments in the implementation of `archive.CopyTo` for exactly what
	// goes into deciding how and whether the source archive needs to be
	// altered for the correct copy behavior.
	_, err = io.Copy(channel, content)
	return err
}

func splitPathDirEntry(path string) (dir, base string) {
	cleanedPath := filepath.Clean(filepath.ToSlash(path))

	if filepath.Base(path) == "." {
		cleanedPath += string(filepath.Separator) + "."
	}

	return filepath.Dir(cleanedPath), filepath.Base(cleanedPath)
}

func (c *HTTPClient) CopyFileToContainer(tarContent io.Reader, dstContainer, dstPath string) (err error) {

	// Prepare destination copy info by stat-ing the container path.
	dstStat, err := c.StatContainerPath(dstContainer, dstPath)

	// If the destination is a symbolic link, we should evaluate it.
	if err == nil && dstStat.Mode&os.ModeSymlink != 0 {
		linkTarget := dstStat.LinkTarget
		if !filepath.IsAbs(linkTarget) {
			// Join with the parent directory.
			dstParent, _ := splitPathDirEntry(dstPath)
			linkTarget = filepath.Join(dstParent, linkTarget)
		}

		dstPath = linkTarget
		dstStat, err = c.StatContainerPath(dstContainer, linkTarget)
	}

	options := types.CopyToContainerOptions{
		ContainerID:               dstContainer,
		Path:                      dstPath,
		Content:                   tarContent,
		AllowOverwriteDirWithFile: false,
	}

	return c.CopyToContainer(context.Background(), options)
}
