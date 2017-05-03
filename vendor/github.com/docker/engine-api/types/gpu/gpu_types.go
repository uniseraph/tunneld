package gpu

type GpuCount struct {
	Count uint
}

type GpuDevice struct {
	Index uint
	Type  string
	Path  string
	Cache uint64
}

type ProcessInfo struct {
	PID       uint
	Name      string
	CacheUsed uint64
}

type GpuDeviceStatus struct {
	Power       uint
	Temperature uint
	TotalCache  uint64
	UsedCache   uint64
	Processes   []*ProcessInfo
}

type GpuDriverVersion struct {
	Version string
}

type GpuControlDevice struct {
	Path string
}

type GpuInfo struct {
	GpuCount          int
	GpuDriverVersion  string
	GpuDevices        []*GpuDevice
	GpuControlDevices []*GpuControlDevice
}
