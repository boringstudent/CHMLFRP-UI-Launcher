import psutil
import os
from typing import List

# 配置参数（直接修改变量值即可）
TARGET_DIR = "C:\\Program Files (x86)\\Huorong\\Sysdiag\\bin"  # 替换为实际目录
SHOW_DETAILS = True  # 是否显示详细信息

def is_subdirectory(child_path: str, parent_path: str) -> bool:
    """安全判断子目录关系（跨平台）"""
    parent = os.path.normcase(os.path.realpath(parent_path))
    child = os.path.normcase(os.path.realpath(child_path))
    return child.startswith(parent + os.sep) or child == parent

def get_target_processes(target_dir: str) -> List[psutil.Process]:
    """获取目标目录及子目录下的所有进程"""
    target_dir = os.path.abspath(target_dir)
    matched = []

    for proc in psutil.process_iter(['pid', 'name', 'cwd', 'exe', 'status']):
        try:
            if not proc.info['cwd']:
                continue
            proc_cwd = os.path.realpath(proc.info['cwd'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
            continue
        except Exception as e:
            if SHOW_DETAILS:
                print(f"⚠️ 进程 {proc.pid} 信息获取失败: {str(e)}")
            continue

        if is_subdirectory(proc_cwd, target_dir):
            matched.append(proc)
            if SHOW_DETAILS:
                print(f"🔍 发现匹配进程 PID:{proc.pid} 路径: {proc_cwd}")

    return matched

def terminate_processes(processes: List[psutil.Process]) -> None:
    """安全终止进程"""
    for proc in processes:
        try:
            if proc.status() == psutil.STATUS_ZOMBIE:
                if SHOW_DETAILS:
                    print(f"⏩ 跳过僵尸进程 PID:{proc.pid}")
                continue

            children = proc.children(recursive=True)
            for child in children:
                try:
                    child.terminate()
                except psutil.NoSuchProcess:
                    continue

            proc.terminate()
            print(f"✅ 已终止进程 PID:{proc.pid} {proc.name()}")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"❌ 终止失败 PID:{proc.pid}: {str(e)}")
        except Exception as e:
            print(f"🔥 意外错误 PID:{proc.pid}: {str(e)}")

def main():
    if not os.path.isdir(TARGET_DIR):
        print(f"❌ 错误：目录不存在 - {TARGET_DIR}")
        return

    try:
        processes = get_target_processes(TARGET_DIR)
        if not processes:
            print(f"ℹ️  {TARGET_DIR} 及其子目录下未发现进程")
            return

        print(f"\\n⚠️ 发现 {len(processes)} 个在 {TARGET_DIR} 及其子目录运行的进程:")
        for p in processes:
            print(f"    ▸ PID:{p.pid} {p.name()}")

        confirm = input("\\n❗ 确认终止这些进程？(y/n): ").strip().lower()
        if confirm == 'y':
            terminate_processes(processes)
            print("🎉 操作完成")
        else:
            print("操作取消")

    except KeyboardInterrupt:
        print("\\n操作中断")

if __name__ == "__main__":
    # 在运行前确保已安装依赖：pip install psutil
    main()
import psutil
import os
from typing import List

# 配置参数（直接修改变量值即可）
TARGET_DIR = "/path/to/your/target_directory"  # 替换为实际目录
SHOW_DETAILS = True  # 是否显示详细信息

def is_subdirectory(child_path: str, parent_path: str) -> bool:
    """安全判断子目录关系（跨平台）"""
    parent = os.path.normcase(os.path.realpath(parent_path))
    child = os.path.normcase(os.path.realpath(child_path))
    return child.startswith(parent + os.sep) or child == parent

def get_target_processes(target_dir: str) -> List[psutil.Process]:
    """获取目标目录及子目录下的所有进程"""
    target_dir = os.path.abspath(target_dir)
    matched = []

    for proc in psutil.process_iter(['pid', 'name', 'cwd', 'exe', 'status']):
        try:
            if not proc.info['cwd']:
                continue
            proc_cwd = os.path.realpath(proc.info['cwd'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
            continue
        except Exception as e:
            if SHOW_DETAILS:
                print(f"⚠️ 进程 {proc.pid} 信息获取失败: {str(e)}")
            continue

        if is_subdirectory(proc_cwd, target_dir):
            matched.append(proc)
            if SHOW_DETAILS:
                print(f"🔍 发现匹配进程 PID:{proc.pid} 路径: {proc_cwd}")

    return matched

def terminate_processes(processes: List[psutil.Process]) -> None:
    """安全终止进程"""
    for proc in processes:
        try:
            if proc.status() == psutil.STATUS_ZOMBIE:
                if SHOW_DETAILS:
                    print(f"⏩ 跳过僵尸进程 PID:{proc.pid}")
                continue

            children = proc.children(recursive=True)
            for child in children:
                try:
                    child.terminate()
                except psutil.NoSuchProcess:
                    continue

            proc.terminate()
            print(f"✅ 已终止进程 PID:{proc.pid} {proc.name()}")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"❌ 终止失败 PID:{proc.pid}: {str(e)}")
        except Exception as e:
            print(f"🔥 意外错误 PID:{proc.pid}: {str(e)}")

def main():
    if not os.path.isdir(TARGET_DIR):
        print(f"❌ 错误：目录不存在 - {TARGET_DIR}")
        return

    try:
        processes = get_target_processes(TARGET_DIR)
        if not processes:
            print(f"ℹ️  {TARGET_DIR} 及其子目录下未发现进程")
            return

        print(f"\\n⚠️ 发现 {len(processes)} 个在 {TARGET_DIR} 及其子目录运行的进程:")
        for p in processes:
            print(f"    ▸ PID:{p.pid} {p.name()}")

        confirm = input("\\n❗ 确认终止这些进程？(y/n): ").strip().lower()
        if confirm == 'y':
            terminate_processes(processes)
            print("🎉 操作完成")
        else:
            print("操作取消")

    except KeyboardInterrupt:
        print("\\n操作中断")

if __name__ == "__main__":
    # 在运行前确保已安装依赖：pip install psutil
    main()
