# 示例代码
# 以下是一个完整的示例，演示如何使用上述函数关闭指定目录下的所有文件。

import os  
  
def list_files(directory):  
    return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]  
  
def close_files(directory):  
    files = list_files(directory)  
    for file in files:  
        file_path = os.path.join(directory, file)  
        with open(file_path, 'rb') as f:  
            f.close()  # 关闭文件  
  
# 使用示例  
directory_path = '/path/to/your/directory'  
close_files(directory_path)  
# 请将/path/to/your/directory替换为你想要关闭文件的目录路径。
