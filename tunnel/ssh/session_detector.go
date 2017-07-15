package ssh

import (
	"io"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/zanecloud/tunneld/tunnel/audit"
)

type RecordFunc func([]byte, bool, *audit.AuditInfo)

var inputIndex = 0
var InputCache = []byte{}

func grammarAnalyse(data []byte) (ready bool, inputMsg string, err error) {
	// byte(13) - enter
	// byte(3) - ctrl+c
	// byte(4) - ctrl+d
	// byte(26) - ctrl+z
	// bytes[27 91 65] - up
	// bytes[27 91 66] - down
	// bytes[27 91 67] - right
	// bytes[27 91 68] - left
	// byte(127) - backspace
	// bytes[27 91 51 126] - delete

	if len(InputCache) >= 1048576 {
		// cache size large than 1MB, reset InputCache
		inputMsg = string(InputCache)
		InputCache = []byte{}
		return true, inputMsg, nil
	}

	switch {
	case len(data) == 1 && data[0] == byte(13):
		// enter input or cache size large than 1MB, reset InputCache
	case len(data) == 1 && data[0] == byte(3):
		InputCache = append(InputCache, []byte("[ctrl+c]")...)
	case len(data) == 1 && data[0] == byte(4):
		InputCache = append(InputCache, []byte("[ctrl+d]")...)
	case len(data) == 1 && data[0] == byte(26):
		InputCache = append(InputCache, []byte("[ctrl+z]")...)
	case len(data) == 3 && data[0] == byte(27) && data[1] == byte(91) && data[2] == byte(65):
		InputCache = append(InputCache, []byte("[up-arrow]")...)
	case len(data) == 3 && data[0] == byte(27) && data[1] == byte(91) && data[2] == byte(66):
		InputCache = append(InputCache, []byte("[down-arrow]")...)
	case len(data) == 3 && data[0] == byte(27) && data[1] == byte(91) && data[2] == byte(67):
		if inputIndex < len(InputCache) {
			inputIndex += 1
		}
		return false, "", nil
	case len(data) == 3 && data[0] == byte(27) && data[1] == byte(91) && data[2] == byte(68):
		if inputIndex > 0 {
			inputIndex -= 1
		}
		return false, "", nil
	case len(data) == 1 && data[0] == byte(127):
		if len(InputCache) > 0 {
			if inputIndex < len(InputCache) {
				if inputIndex > 0 {
					temp := make([]byte, len(InputCache)-1)
					copy(temp, InputCache[:inputIndex-1])
					copy(temp[inputIndex-1:], InputCache[inputIndex:])
					InputCache = temp
					inputIndex -= 1
				}
			} else {
				inputIndex -= 1
				InputCache = InputCache[:len(InputCache)-1]
			}
		}
		return false, "", nil
	case len(data) == 4 && data[0] == byte(27) && data[1] == byte(91) && data[2] == byte(51) && data[3] == byte(126):
		if len(InputCache) > 0 {
			if inputIndex < len(InputCache) {
				temp := make([]byte, len(InputCache)-1)
				copy(temp, InputCache[:inputIndex])
				copy(temp[inputIndex:], InputCache[inputIndex+1:])
				InputCache = temp
			}
		}
		return false, "", nil
	default:
		if inputIndex != len(InputCache) {
			temp := make([]byte, len(InputCache)+len(data))
			copy(temp, InputCache[:inputIndex])
			copy(temp[inputIndex:], data)
			copy(temp[inputIndex+len(data):], InputCache[inputIndex:])
			InputCache = temp
		} else {
			InputCache = append(InputCache, data...)
		}
		inputIndex += len(data)
		return false, "", nil
	}

	inputMsg = string(InputCache)
	inputIndex = 0
	InputCache = []byte{}
	return true, inputMsg, nil
}

func recordInputData(data []byte, sync bool, ai *audit.AuditInfo) {
	ready, inputMsg, err := grammarAnalyse(data)
	if err != nil {
		// ignore error now
		logrus.Debugf("get error with token: %s, user: %s, when record data: %v \n", ai.Token, ai.User, data)
	}
	if ready {
		// send msg to audit system
		_, err := ai.AuditClient.AuditLog(&audit.AuditLogRequest{
			Token:     ai.Token,
			User:      ai.User,
			Command:   inputMsg,
			Output:    "",
			Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		})
		if err != nil {
			logrus.Debugf("AuditLog failed with token: %s, user: %s, command: %s", ai.Token, ai.User, inputMsg)
		}
	}
}

func recordOutputData(data []byte, sync bool, ai *audit.AuditInfo) {
	// not implement
}

func SessionInputCopy(dst io.Writer, src io.Reader, buf []byte, ai *audit.AuditInfo) (written int64, err error) {
	return SessionCopy(dst, src, buf, recordInputData, ai)
}

func SessionOutputCopy(dst io.Writer, src io.Reader, buf []byte, ai *audit.AuditInfo) (written int64, err error) {
	return SessionCopy(dst, src, buf, recordOutputData, ai)
}

// SessionCopy is the actual implementation of io.Copy and io.CopyBuffer.
// if buf is nil, one is allocated.
func SessionCopy(dst io.Writer, src io.Reader, buf []byte, recordData RecordFunc, ai *audit.AuditInfo) (written int64, err error) {
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	//if wt, ok := src.(io.WriterTo); ok {
	//	return wt.WriteTo(dst)
	//}
	//// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	//if rt, ok := dst.(io.ReaderFrom); ok {
	//	return rt.ReadFrom(src)
	//}
	if buf == nil {
		buf = make([]byte, 32*1024)
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// NOTE(tongkai): here we inject session detector to record data
			recordData(buf[0:nr], false, ai)

			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}
