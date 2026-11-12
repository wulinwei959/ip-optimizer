package app

import "time"

// timedMutex 是带超时获取能力的互斥锁：内部用容量 1 的 channel 当令牌。
// lock 阻塞取令牌，tryLockTimeout 限时取令牌，拿不到立即返回 false 而非永久排队。
// 不用 sync.Mutex.TryLock 轮询：官方标注 starvation-prone，而定时轮常驻排队者正是
// 本场景最忌讳的。
type timedMutex struct {
	ch chan struct{}
}

func newTimedMutex() *timedMutex {
	ch := make(chan struct{}, 1)
	ch <- struct{}{}
	return &timedMutex{ch: ch}
}

func (m *timedMutex) lock() {
	<-m.ch
}

func (m *timedMutex) unlock() {
	m.ch <- struct{}{}
}

func (m *timedMutex) tryLockTimeout(d time.Duration) bool {
	if d <= 0 {
		select {
		case <-m.ch:
			return true
		default:
			return false
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-m.ch:
		return true
	case <-timer.C:
		return false
	}
}
