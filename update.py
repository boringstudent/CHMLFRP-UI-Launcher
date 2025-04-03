import os
import zipfile
import psutil
import sys
import re
import time
import ctypes
import subprocess
from typing import List
from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout,
                             QWidget, QProgressBar, QLabel, QTextEdit, QMessageBox,
                             QHBoxLayout, QFrame)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QIcon, QFont


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1)


class WorkerThread(QThread):
    update_progress = pyqtSignal(int, str)
    finished = pyqtSignal(bool, str)

    def __init__(self, target_dir):
        super().__init__()
        self.target_dir = target_dir
        self.current_pid = os.getpid()

    def run(self):
        try:
            self.update_progress.emit(10, "正在终止目标进程...")
            processes = self.get_target_processes(self.target_dir)

            if processes:
                self.terminate_processes(processes)
                self.update_progress.emit(20, f"已终止 {len(processes)} 个进程")
                time.sleep(2)
            else:
                self.update_progress.emit(20, "没有需要终止的进程")

            self.update_progress.emit(30, "正在查找最新更新包...")
            zip_file = self.find_latest_zip_file(self.target_dir)
            if not zip_file:
                self.finished.emit(False, "未找到 CUL*.zip 更新包")
                return

            self.update_progress.emit(40, f"正在解压 {os.path.basename(zip_file)}...")
            self.extract_zip_with_permissions(zip_file, self.target_dir)

            self.update_progress.emit(80, "清理旧版本更新包...")
            self.cleanup_old_zips(zip_file)

            self.update_progress.emit(90, "准备启动应用程序...")
            self.finished.emit(True, "更新完成!")
            self.update_progress.emit(100, "就绪")

        except Exception as e:
            self.finished.emit(False, f"错误: {str(e)}")

    def is_subdirectory(self, child_path: str, parent_path: str) -> bool:
        parent = os.path.normcase(os.path.realpath(parent_path))
        child = os.path.normcase(os.path.realpath(child_path))
        return child.startswith(parent + os.sep) or child == parent

    def get_target_processes(self, target_dir: str) -> List[psutil.Process]:
        target_dir = os.path.abspath(target_dir)
        matched = []

        for proc in psutil.process_iter(['pid', 'name', 'cwd', 'exe', 'status']):
            try:
                if proc.pid == self.current_pid:
                    continue

                if not proc.info['cwd']:
                    continue

                proc_cwd = os.path.realpath(proc.info['cwd'])
                proc_exe = proc.info['exe']

                # 排除包含"_internal"和"CUL_update.exe"的进程
                if "_internal" in proc_cwd or "_internal" in (proc_exe or ""):
                    continue
                if proc.info['name'] == "CUL_update.exe":
                    continue

            except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
                continue
            except Exception:
                continue

            if self.is_subdirectory(proc_cwd, target_dir):
                matched.append(proc)

        return matched

    def terminate_processes(self, processes: List[psutil.Process]) -> None:
        for proc in processes:
            try:
                if proc.pid == self.current_pid:
                    continue
                if proc.status() == psutil.STATUS_ZOMBIE:
                    continue
                children = proc.children(recursive=True)
                for child in children:
                    try:
                        if child.pid == self.current_pid:
                            continue
                        child.terminate()
                    except psutil.NoSuchProcess:
                        continue

                proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def find_latest_zip_file(self, directory: str) -> str:
        zip_files = []
        pattern = re.compile(r'CUL(\d+)\.(\d+)\.(\d+)\.zip', re.IGNORECASE)

        for file in os.listdir(directory):
            match = pattern.fullmatch(file)
            if match:
                version = tuple(map(int, match.groups()))
                zip_files.append((version, file))
        if not zip_files:
            return ""
        zip_files.sort(reverse=True, key=lambda x: x[0])
        return os.path.join(directory, zip_files[0][1])

    def extract_zip_with_permissions(self, zip_path: str, extract_to: str) -> None:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            total = len(zip_ref.infolist())
            for i, file in enumerate(zip_ref.infolist()):
                try:
                    file_path = os.path.join(extract_to, file.filename)
                    if file.filename.endswith('/'):
                        continue
                    if file.filename.startswith('CHMLFRP_UI.dist/'):
                        file_path = os.path.join(extract_to, file.filename.replace('CHMLFRP_UI.dist/', '', 1))
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    if os.path.exists(file_path):
                        try:
                            os.chmod(file_path, 0o777)
                        except:
                            pass
                    with open(file_path, 'wb') as out_file:
                        out_file.write(zip_ref.read(file.filename))
                    try:
                        os.chmod(file_path, 0o666)  # Read/write for everyone
                    except:
                        pass

                    progress = 40 + int(40 * (i / total))
                    self.update_progress.emit(progress, f"解压中: {file.filename}")
                except Exception as e:
                    self.update_progress.emit(progress, f"解压失败 {file.filename}: {str(e)}")

    def cleanup_old_zips(self, keep_zip: str) -> None:
        pattern = re.compile(r'CUL(\d+)\.(\d+)\.(\d+)\.zip', re.IGNORECASE)
        keep_file = os.path.basename(keep_zip)

        for file in os.listdir(self.target_dir):
            if pattern.fullmatch(file) and file != keep_file:
                try:
                    file_path = os.path.join(self.target_dir, file)
                    try:
                        os.chmod(file_path, 0o777)
                    except:
                        pass
                    os.remove(file_path)
                    self.update_progress.emit(85, f"已删除旧版本: {file}")
                except Exception as e:
                    self.update_progress.emit(85, f"删除旧版本失败 {file}: {e}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # 修改为当前脚本所在目录的上一级目录
        self.target_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        if not is_admin():
            self.show_admin_warning()
            run_as_admin()
            sys.exit(0)

        self.setup_ui()
        self.setWindowTitle("CUL 更新工具")

        icon_path = os.path.join(self.target_dir, "favicon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

    def show_admin_warning(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setText("需要管理员权限")
        msg.setInformativeText("此操作需要管理员权限才能继续。请允许程序以管理员身份运行。")
        msg.setWindowTitle("权限提示")
        msg.exec()

    def setup_ui(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        header_frame = QFrame()
        header_frame.setFrameShape(QFrame.Shape.StyledPanel)
        header_frame.setStyleSheet("background-color: #2c3e50; border-radius: 8px;")
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(15, 15, 15, 15)

        title = QLabel("CUL 自动更新工具")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 22px;
                font-weight: bold;
            }
        """)

        header_layout.addWidget(title)
        header_frame.setLayout(header_layout)
        main_layout.addWidget(header_frame)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 4px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 3px;
            }
        """)
        main_layout.addWidget(self.progress_bar)

        self.progress_percent = QLabel("0%")
        self.progress_percent.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_percent.setStyleSheet("font-size: 14px; color: #3498db;")
        main_layout.addWidget(self.progress_percent)

        self.status_label = QLabel("就绪")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: #7f8c8d;
                font-style: italic;
            }
        """)
        main_layout.addWidget(self.status_label)

        # Log output
        log_frame = QFrame()
        log_frame.setFrameShape(QFrame.Shape.StyledPanel)
        log_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #ddd;
            }
        """)
        log_layout = QVBoxLayout()
        log_layout.setContentsMargins(5, 5, 5, 5)

        log_title = QLabel("操作日志")
        log_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        log_layout.addWidget(log_title)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("""
            QTextEdit {
                border: none;
                font-family: Consolas, monospace;
                font-size: 12px;
            }
        """)
        log_layout.addWidget(self.log_output)
        log_frame.setLayout(log_layout)
        main_layout.addWidget(log_frame)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)

        self.start_button = QPushButton("开始更新")
        self.start_button.setMinimumHeight(40)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 16px;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #2ecc71;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        self.start_button.clicked.connect(self.start_update)
        button_layout.addWidget(self.start_button)

        main_layout.addLayout(button_layout)

        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        self.setMinimumSize(400, 500)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #ecf0f1;
            }
            QLabel {
                margin: 2px;
            }
        """)

    def start_update(self):
        self.start_button.setEnabled(False)
        self.log_output.clear()
        self.log_output.append(f"开始更新流程...")
        self.log_output.append(f"目标目录: {self.target_dir}")

        self.worker = WorkerThread(self.target_dir)
        self.worker.update_progress.connect(self.update_progress)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

    def update_progress(self, value: int, message: str):
        self.progress_bar.setValue(value)
        self.progress_percent.setText(f"{value}%")
        self.status_label.setText(message)
        self.log_output.append(message)

    def on_finished(self, success: bool, message: str):
        self.log_output.append(message)
        if success:
            QMessageBox.information(self, "完成", "更新成功完成!")
            QTimer.singleShot(1000, self.launch_and_exit)
        else:
            self.start_button.setEnabled(True)
            QMessageBox.warning(self, "错误", message)

    def launch_and_exit(self):
        exe_path = os.path.join(self.target_dir, "CHMLFRP_UI.exe")
        if os.path.exists(exe_path):
            try:
                subprocess.Popen([exe_path], cwd=self.target_dir)
            except Exception as e:
                self.log_output.append(f"启动应用程序失败: {e}")
        self.close()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    font = QFont("Microsoft YaHei", 10)
    app.setFont(font)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())
    # pyinstaller --noconsole --icon=favicon.ico --name=CUL_update update.py