import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import time
import base64
import re
_invisible_pattern = re.compile(r'[\x00-\x08\x0A\x0B\x0C\x0D\x0E-\x1F\x20\x7F\u200B-\u200D\u2060\uFEFF]')

def fast_clean(text):
    return _invisible_pattern.sub('', text)

import hashlib
from typing import Union

def compute_md5(data: Union[str, bytes, bytearray, None], is_file: bool = False) -> str:
    """
    计算字符串、二进制数据或文件的 MD5
    :param data: 输入数据（字符串/文件路径）
    :param is_file: 是否为文件路径
    :return: MD5 十六进制字符串
    """
    if is_file:
        return md5_large_file(data)
    elif isinstance(data, str):
        return hashlib.md5(data.encode('utf-8')).hexdigest()
    elif isinstance(data, (bytes, bytearray)):
        return hashlib.md5(data).hexdigest()
    else:
        raise TypeError("不支持的数据类型")

class EnhancedTextTool:
    def __init__(self, root):
        self.root = root
        self.root.title("增强版字符串处理工具")
        self.root.geometry("1200x800")

        # 主框架
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 左侧原文本区（含字数统计）
        self.left_frame = ttk.LabelFrame(self.main_frame, text="原文本区")
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.input_text, self.input_count = self.create_text_area_with_counter(self.left_frame)

        # 中间功能按钮区
        self.center_frame = ttk.Frame(self.main_frame)
        self.center_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10)
        self.create_buttons()

        # 右侧结果区（含字数统计）
        self.right_frame = ttk.LabelFrame(self.main_frame, text="结果区")
        self.right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.output_text, self.output_count = self.create_text_area_with_counter(self.right_frame)

        # 菜单栏
        self.create_menu()

        # 绑定文本变化事件
        self.input_text.bind("<<Modified>>", lambda e: self.update_counter(e, self.input_count))
        self.output_text.bind("<<Modified>>", lambda e: self.update_counter(e, self.output_count))



    def create_text_area_with_counter(self, parent):
        """创建带滚动条和字数统计的文本框区域"""
        container = ttk.Frame(parent)
        container.pack(fill=tk.BOTH, expand=True)

        # 文本框
        text_widget = tk.Text(container, wrap=tk.WORD, undo=True)
        text_widget.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # 滚动条
        scroll = ttk.Scrollbar(container, command=text_widget.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.config(yscrollcommand=scroll.set)

        # 字数统计栏
        counter_frame = ttk.Frame(container)
        counter_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)
        ttk.Label(counter_frame, text="字数:").pack(side=tk.LEFT)
        count_label = ttk.Label(counter_frame, text="0", foreground="blue")
        count_label.pack(side=tk.LEFT)

        return text_widget, count_label

    def create_buttons(self):
        """创建垂直排列的功能按钮"""
        buttons = [
            ("打开文件", self.open_file),
            ("保存结果", self.save_result),
            ("清空输入", lambda: self.clear_text(self.input_text)),
            ("清空结果", lambda: self.clear_text(self.output_text)),
            ("→字符串转HEX→", self.to_hex),
            ("→HEX转字符串→", self.hex_to_utf8),
            ("→加空格→", self.add_spaces),
            ("→ 大写转换 →", self.to_upper),
            ("→ 小写转换 →", self.to_lower),
            ("→ 删空格 →", self.remove_spaces),
            ("→转GBK HEX→", self.to_gbk_hex),
            ("→GBK HEX转str→", self.gbk_hex_to_str),
            ("→XOR→", self.hex_str_xor),           
            ("→MD5→", self.str_to_md5),
            ("→MD5 HEX→", self.hex_to_md5),
            ("→BASE64 Enc→", self.str_base64),
            ("→hex BASE64 Enc→", self.hexstr_base64),
            ("→BASE64 Dec→", self.base64_decode),
            ("→TLV→", self.tlv_decode),
            ("→ 统计详情 →", self.show_stats)
        ]

        for text, cmd in buttons:
            btn = ttk.Button(self.center_frame, text=text, command=cmd, width=15)
            btn.pack(pady=5, fill=tk.X)

    def create_menu(self):
        """创建菜单系统"""
        menu_bar = tk.Menu(self.root)
        
        # 文件菜单
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="打开文件", command=self.open_file)
        file_menu.add_command(label="保存结果", command=self.save_result)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)
        
        # 编辑菜单
        edit_menu = tk.Menu(menu_bar, tearoff=0)
        edit_menu.add_command(label="复制结果", command=self.copy_result)

        # help菜单
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="关于", command=self.about)
        
        menu_bar.add_cascade(label="文件", menu=file_menu)
        menu_bar.add_cascade(label="编辑", menu=edit_menu)
        menu_bar.add_cascade(label="帮助", menu=help_menu)
        self.root.config(menu=menu_bar)

    # 核心功能 --------------------------------------------------
    def update_counter(self, event, label):
        """实时更新字数统计"""
        text_widget = event.widget
        if text_widget.edit_modified():
            content = text_widget.get(1.0, tk.END).rstrip('\n')
            contentn = fast_clean(content)
            char_count = len(contentn)  # 统计字符数
            word_count = char_count//2  # 统计单词数
            label.config(text=f"{char_count} 字符 / {word_count} 字节")
            text_widget.edit_modified(False)  # 重置修改标志

    def open_file(self):
        """加载文件到输入区"""
        file_path = filedialog.askopenfilename(filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.input_text.delete(1.0, tk.END)
                    self.input_text.insert(tk.END, f.read())
            except Exception as e:
                messagebox.showerror("错误", f"文件读取失败:\n{str(e)}")

    def save_result(self):
        """保存结果区内容"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.output_text.get(1.0, tk.END))
                messagebox.showinfo("成功", "文件保存成功！")
            except Exception as e:
                messagebox.showerror("错误", f"保存失败:\n{str(e)}")

    def clear_text(self, text_widget):
        """清空指定文本框"""
        text_widget.delete(1.0, tk.END)

    def to_upper(self):
        """大写转换"""
        original = self.input_text.get(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, original.upper())

    def to_lower(self):
        """小写转换"""
        original = self.input_text.get(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, original.lower())

    def remove_spaces(self):
        """删除所有空格"""
        original = self.input_text.get(1.0, tk.END)
        result = original.replace(" ", "").replace("\t", "")
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, result)

    def add_spaces(self):
        """每两个字符加空格"""
        original = self.input_text.get(1.0, tk.END)
        result = ' '.join(original[i:i+2] for i in range(0, len(original), 2))
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, result)


    def str_to_hex(self, text, encoding='utf-8', delimiter=''):
        """
        将字符串转换为 HEX 格式
        :param text: 输入字符串
        :param encoding: 编码格式（默认 utf-8）
        :param delimiter: 分隔符（如 ' ', ':'）
        :return: HEX 字符串
        """
        hex_bytes = text.encode(encoding)
        hex_str = hex_bytes.hex()
        if delimiter:
            hex_str = delimiter.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        return hex_str.upper()
    def to_hex(self):
        """转换成hex"""
        original = self.input_text.get(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        out_text=self.str_to_hex(original.strip(),encoding='utf-8', delimiter=' ')
        print(out_text)
        self.output_text.insert(tk.END, out_text)

    def hex_process_enhanced(self,input_str, encoding='utf-8'):
        hex_str = fast_clean(input_str)
        
        if not hex_str:
            return "输入为空"
        
        # 检查是否为合法HEX字符
        if not all(c in "0123456789abcdefABCDEF" for c in hex_str):
            return "包含非HEX字符"
        
        # 处理奇数长度：末尾补零
        if len(hex_str) % 2 != 0:
            hex_str += '0'  # 或 return "HEX长度必须为偶数"
        
        try:
            bytes_data = bytes.fromhex(hex_str)
            decoded_str = bytes_data.decode(encoding, errors='replace')  # 替换无效字符
            return decoded_str
        except Exception as e:
            return f"解码错误: {str(e)}"
    def hex_to_utf8(self):
        """hex转换成字符串"""
        original = self.input_text.get(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        out_text=self.hex_process_enhanced(original)
        print(out_text)
        self.output_text.insert(tk.END, out_text)

    def to_gbk_hex(self):
        """转换成hex"""
        original = self.input_text.get(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        out_text=self.str_to_hex(original.strip(),encoding='gbk', delimiter=' ')
        print(out_text)
        self.output_text.insert(tk.END, out_text)

    def gbk_hex_to_str(self):
        """gbk hex转换成字符串"""
        original = self.input_text.get(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        out_text=self.hex_process_enhanced(original,encoding='gbk')
        print(out_text)
        self.output_text.insert(tk.END, out_text)

    def hex_process_xor(self,input_str):
        hex_str = fast_clean(input_str)
        
        if not hex_str:
            return "输入为空"
        
        # 检查是否为合法HEX字符
        if not all(c in "0123456789abcdefABCDEF" for c in hex_str):
            return "包含非HEX字符"
        
        # 处理奇数长度：末尾补零
        if len(hex_str) % 2 != 0:
            hex_str += '0'  # 或 return "HEX长度必须为偶数"
        
        try:
            bytes_data = bytes.fromhex(hex_str)
            res = 0x00
            for c in bytes_data:
                res ^=c
            
            return "%02X" % (res)
        except Exception as e:
            return f"解码错误: {str(e)}"
    def hex_str_xor(self):
        original = self.input_text.get(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        out_text=self.hex_process_xor(original)
        print(out_text)
        self.output_text.insert(tk.END, out_text)

    def str_to_md5(self):
        original = self.input_text.get(1.0, tk.END).rstrip('\n').replace(' ','')
        self.output_text.delete(1.0, tk.END)
        out_text=hashlib.md5(original.encode('utf-8')).hexdigest().upper()
        print(out_text)
        self.output_text.insert(tk.END, out_text)

    def hex_process_md5(self,input_str):
        hex_str = fast_clean(input_str)
        
        if not hex_str:
            return "输入为空"
        
        # 检查是否为合法HEX字符
        if not all(c in "0123456789abcdefABCDEF" for c in hex_str):
            return "包含非HEX字符"
        
        # 处理奇数长度：末尾补零
        if len(hex_str) % 2 != 0:
            hex_str += '0'  # 或 return "HEX长度必须为偶数"
        
        try:
            bytes_data = bytes.fromhex(hex_str)
            md5str=hashlib.md5(bytes_data).hexdigest().upper()
            return md5str
        except Exception as e:
            return f"解码错误: {str(e)}"
    def hex_to_md5(self):
        original = self.input_text.get(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        out_text=self.hex_process_md5(original)
        print(out_text)
        self.output_text.insert(tk.END, out_text)

    def hexstr_base64(self):
        original = self.input_text.get(1.0, tk.END).rstrip('\n')
        self.output_text.delete(1.0, tk.END)

        #将字符串编码-->字节码，
        hex_str = fast_clean(original)
        
        if not hex_str:
            return "输入为空"
        
        # 检查是否为合法HEX字符
        if not all(c in "0123456789abcdefABCDEF" for c in hex_str):
            return "包含非HEX字符"
        
        # 处理奇数长度：末尾补零
        if len(hex_str) % 2 != 0:
            hex_str += '0'  # 或 return "HEX长度必须为偶数"

        bytes_by_s=bytes.fromhex(hex_str)
        b64_encode_bytes=base64.b64encode(bytes_by_s) #base64编码
        print(b64_encode_bytes)

        out_text=b64_encode_bytes
        print(out_text)
        self.output_text.insert(tk.END, out_text)

    def str_base64(self):
        original = self.input_text.get(1.0, tk.END).rstrip('\n')
        self.output_text.delete(1.0, tk.END)
        bytes_by_s=original.encode() #将字符串编码-->字节码，
        b64_encode_bytes=base64.b64encode(bytes_by_s) #base64编码
        print(b64_encode_bytes)

        out_text=b64_encode_bytes
        print(out_text)
        self.output_text.insert(tk.END, out_text)

    def base64_decode(self):
        original = self.input_text.get(1.0, tk.END).rstrip('\n').replace(' ','')
        self.output_text.delete(1.0, tk.END)
        b64_decode_bytes=base64.b64decode(original)
        print(b64_decode_bytes)
        out_text=b64_decode_bytes.hex()
        print(out_text)
        self.output_text.insert(tk.END, out_text)

    def tlv_decode(self):
        original = self.input_text.get(1.0, tk.END).rstrip('\n').replace(' ','')
        self.output_text.delete(1.0, tk.END)
        import emv_tlv
        tlv_hex=bytes.fromhex(original)
        tmp_text=emv_tlv.parse_tlv(tlv_hex)
        out_text=emv_tlv.pretty_print_tlv(tmp_text)
        print(out_text)
        self.output_text.insert(tk.END, out_text)

    def show_stats(self):
        """显示详细统计信息"""
        input_content = self.input_text.get(1.0, tk.END)
        output_content = self.output_text.get(1.0, tk.END)
        
        stats = f"""【输入区统计】
字符数: {len(input_content.strip())}
单词数: {len(input_content.strip().split())}

【输出区统计】
字符数: {len(output_content.strip())}
单词数: {len(output_content.strip().split())}"""
        
        messagebox.showinfo("统计详情", stats)

    def copy_result(self):
        """复制结果到剪贴板"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.output_text.get(1.0, tk.END))

    def about(self):
        """关于内容"""
        messagebox.showinfo("版本", "V1.0\r\nliusong")

overticks=1779000000
#overticks=1679000000
timeticks = int(time.time())


if __name__ == "__main__":

    if timeticks>overticks:
        messagebox.showinfo("错误", "程序已过期")
    else:
        root = tk.Tk()
        # 加载 PNG 图片
        photo = tk.PhotoImage(file="logo.png")
        root.iconphoto(True, photo)  # True 表示同时设置任务栏图标
    
        app = EnhancedTextTool(root)
        root.mainloop()