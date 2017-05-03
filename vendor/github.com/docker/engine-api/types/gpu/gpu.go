package gpu

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
)

var (
	GPUCmd = "docker-gpu"
)

func Count() (*GpuCount, error) {
	args := []string{
		"count",
	}
	out, err := exec.Command(GPUCmd, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %q", err.Error(), out)
	}
	var gpuCount GpuCount
	if err := json.Unmarshal(out, &gpuCount); err != nil {
		return nil, err
	}
	return &gpuCount, nil
}

func List() ([]*GpuDevice, error) {
	args := []string{
		"list",
	}
	out, err := exec.Command(GPUCmd, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %q", err.Error(), out)
	}
	var gpuDevices []*GpuDevice
	if err := json.Unmarshal(out, &gpuDevices); err != nil {
		return nil, err
	}
	return gpuDevices, nil
}

func Get(index uint) (*GpuDevice, error) {
	args := []string{
		"get",
		strconv.FormatUint(uint64(index), 10),
	}
	out, err := exec.Command(GPUCmd, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %q", err.Error(), out)
	}
	var gpuDevice GpuDevice
	if err := json.Unmarshal(out, &gpuDevice); err != nil {
		return nil, err
	}
	return &gpuDevice, nil
}

func Status(index uint) (*GpuDeviceStatus, error) {
	args := []string{
		"status",
		strconv.FormatUint(uint64(index), 10),
	}
	out, err := exec.Command(GPUCmd, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %q", err.Error(), out)
	}
	var gpuStatus GpuDeviceStatus
	if err := json.Unmarshal(out, &gpuStatus); err != nil {
		return nil, err
	}
	return &gpuStatus, nil
}

func Driver() (*GpuDriverVersion, error) {
	args := []string{
		"driver",
	}
	out, err := exec.Command(GPUCmd, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %q", err.Error(), out)
	}
	var gpuDriver GpuDriverVersion
	if err := json.Unmarshal(out, &gpuDriver); err != nil {
		return nil, err
	}
	return &gpuDriver, nil
}

func Control() ([]*GpuControlDevice, error) {
	args := []string{
		"control",
	}
	out, err := exec.Command(GPUCmd, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %q", err.Error(), out)
	}
	var gpuControlDevices []*GpuControlDevice
	if err := json.Unmarshal(out, &gpuControlDevices); err != nil {
		return nil, err
	}
	return gpuControlDevices, nil
}

func Info() (*GpuInfo, error) {
	gpuDevices, err := List()
	if err != nil {
		return nil, fmt.Errorf("Could not get gpu devices: %v", err)
	}
	gpuControlDevices, err := Control()
	if err != nil {
		return nil, fmt.Errorf("Could not get gpu control devices: %v", err)
	}
	gpuDriver, err := Driver()
	if err != nil {
		return nil, fmt.Errorf("Could not get gpu driver: %v", err)
	}

	if len(gpuDevices) == 0 {
		return nil, nil
	}
	gpuDriverVersion := ""
	if gpuDriver != nil {
		gpuDriverVersion = gpuDriver.Version
	}
	gpus := &GpuInfo{
		GpuCount:          len(gpuDevices),
		GpuDriverVersion:  gpuDriverVersion,
		GpuDevices:        gpuDevices,
		GpuControlDevices: gpuControlDevices,
	}
	return gpus, nil
}
