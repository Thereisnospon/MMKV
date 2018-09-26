/*
 * Tencent is pleased to support the open source community by making
 * MMKV available.
 *
 * Copyright (C) 2018 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Licensed under the BSD 3-Clause License (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *       https://opensource.org/licenses/BSD-3-Clause
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "InterProcessLock.h"
#include "MMKVLog.h"
#include <unistd.h>

static short LockType2FlockType(LockType lockType) {
    switch (lockType) {
        case SharedLockType:
            return F_RDLCK;
        case ExclusiveLockType:
            return F_WRLCK;
    }
}

FileLock::FileLock(int fd) : m_fd(fd), m_sharedLockCount(0), m_exclusiveLockCount(0) {
    m_lockInfo.l_type = F_WRLCK;
    m_lockInfo.l_start = 0;
    m_lockInfo.l_whence = SEEK_SET;
    m_lockInfo.l_len = 0;
    m_lockInfo.l_pid = 0;
}

bool FileLock::doLock(LockType lockType, int cmd) {
    bool unLockFirstIfNeeded = false;

    if (lockType == SharedLockType) {
        m_sharedLockCount++;
        // don't want shared-lock to break any existing locks
        //如果加本次共享锁之前，已经有了共享锁或者排它锁。那么直接返回。（防止break现有的锁）
        if (m_sharedLockCount > 1 || m_exclusiveLockCount > 0) {
            return true;
        }
    } else {
        m_exclusiveLockCount++;
        // don't want exclusive-lock to break existing exclusive-locks
        //如果加本次排他锁之前已经有了排他锁。直接返回。
        if (m_exclusiveLockCount > 1) {
            return true;
        }
        // prevent deadlock
        // 加本次排他锁之前已经有了共享锁，
        if (m_sharedLockCount > 0) {
            unLockFirstIfNeeded = true;
        }
    }

    m_lockInfo.l_type = LockType2FlockType(lockType);
    //需要先放弃现有锁
    if (unLockFirstIfNeeded) {
        // try lock
        //尝试 非阻塞加锁
        auto ret = fcntl(m_fd, F_SETLK, &m_lockInfo);
        //尝试加锁成功，直接返回成功
        if (ret == 0) {
            return true;
        }
        // lets be gentleman: unlock my shared-lock to prevent deadlock
        // 当前锁有共享锁，并且尝试加排他锁失败，说明其他进程有排它锁，当前进程主动放弃共享锁，防止死锁
        auto type = m_lockInfo.l_type;
        m_lockInfo.l_type = F_UNLCK;
        //解除当前锁
        ret = fcntl(m_fd, F_SETLK, &m_lockInfo);
        if (ret != 0) {
            MMKVError("fail to try unlock first fd=%d, ret=%d, error:%s", m_fd, ret,
                      strerror(errno));
        }
        m_lockInfo.l_type = type;
    }
    //加锁（阻塞/非阻塞)
    auto ret = fcntl(m_fd, cmd, &m_lockInfo);
    if (ret != 0) {
        MMKVError("fail to lock fd=%d, ret=%d, error:%s", m_fd, ret, strerror(errno));
        return false;
    } else {
        return true;
    }
}

bool FileLock::lock(LockType lockType) {
    //阻塞加锁
    return doLock(lockType, F_SETLKW);
}

bool FileLock::try_lock(LockType lockType) {
    //非阻塞加锁
    return doLock(lockType, F_SETLK);
}

bool FileLock::unlock(LockType lockType) {
    bool unlockToSharedLock = false;

    if (lockType == SharedLockType) {
        //当前没有共享锁，返回false
        if (m_sharedLockCount == 0) {
            return false;
        }
        m_sharedLockCount--;
        // don't want shared-lock to break any existing locks
        //如果解除本次共享锁仍然有 锁，不进行真正的解锁
        if (m_sharedLockCount > 0 || m_exclusiveLockCount > 0) {
            return true;
        }
    } else {
        //当前没有排他锁，返回
        if (m_exclusiveLockCount == 0) {
            return false;
        }
        m_exclusiveLockCount--;
        //仍然有排他锁
        if (m_exclusiveLockCount > 0) {
            return true;
        }
        // restore shared-lock when all exclusive-locks are done
        //排他锁已全部解除，还有共享锁，（锁降级
        if (m_sharedLockCount > 0) {
            unlockToSharedLock = true;
        }
    }
    //假如之前曾经持有共享锁，那么我们不能直接释放掉排他锁，这样会导致读锁也解了。我们应该加一个共享锁，将锁降级。
    //没有曾经持有共享锁，直接解锁
    m_lockInfo.l_type = static_cast<short>(unlockToSharedLock ? F_RDLCK : F_UNLCK);
    auto ret = fcntl(m_fd, F_SETLK, &m_lockInfo);
    if (ret != 0) {
        MMKVError("fail to unlock fd=%d, ret=%d, error:%s", m_fd, ret, strerror(errno));
        return false;
    } else {
        return true;
    }
}
