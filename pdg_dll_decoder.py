#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PDG Decoder Standalone Tool
独立的PDG解码命令行工具
"""

import os
import sys
import struct
import argparse
from pathlib import Path
from ctypes import *
from PIL import Image


class PDG:
    """PDG文件属性解析类"""
    
    def __init__(self, input_file):
        self.PDG_VERSION = 0
        self.OFFSET_OPTIONAL_HEADER = 0
        self.PDG_TYPE = 0
        self.X_PIX = 0
        self.Y_PIX = 0
        self.ColorDepth = 0
        self.OFFSET_PDG_DATA = 0
        self.SIZE = 0
        self.KEY_DATA = 0
        self.SS_USER_KEY = 0
        self.IMG_TYPE = self._detect_file_type(input_file)
        self.ERROR = 'SUCCESS PDG FILE'
        self.MODE = '1'
        self.path = input_file
        self.name = os.path.basename(input_file)

        if self.IMG_TYPE != 'pdg':
            self.PDG_TYPE = None
            self.PDG_VERSION = None
            self.SIZE = os.path.getsize(input_file)
            try:
                img = Image.open(input_file)
                self.X_PIX = img.width
                self.Y_PIX = img.height
                self.MODE = img.mode
                self.ERROR = 'SUCCESS ' + self.IMG_TYPE + ' FILE'
            except:
                self.X_PIX = 0
                self.Y_PIX = 0
                self.ERROR = 'UNEXPECTED FILE'
        
        if self.IMG_TYPE == 'pdg':
            self._parse_pdg_header(input_file)

    def _detect_file_type(self, file_path):
        """检测文件类型"""
        if isinstance(file_path, str):
            with open(file_path, 'rb') as f:
                header = f.read(34)
        else:
            header = file_path[:34]
        
        # PDG格式检测
        if len(header) >= 4 and header[0:4] == b'\x00\x00\x02\x00':
            return 'pdg'
        # JPEG格式
        if len(header) >= 2 and header[0:2] == b'\xff\xd8':
            return 'jpeg'
        # PNG格式
        if len(header) >= 8 and header[0:8] == b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a':
            return 'png'
        # BMP格式
        if len(header) >= 2 and header[0:2] == b'\x42\x4d':
            return 'bmp'
        # TIFF格式
        if len(header) >= 4 and (header[0:4] == b'\x49\x49\x2a\x00' or header[0:4] == b'\x4d\x4d\x00\x2a'):
            return 'tiff'
        # GIF格式
        if len(header) >= 6 and (header[0:6] == b'\x47\x49\x46\x38\x37\x61' or header[0:6] == b'\x47\x49\x46\x38\x39\x61'):
            return 'gif'
        
        return 'unknown'

    def _parse_pdg_header(self, input_file):
        """解析PDG文件头"""
        with open(input_file, 'rb+') as file:
            header_byte = file.read(140)
            header_byte_list = bytearray(header_byte)
            
            self.PDG_VERSION = header_byte_list[2]
            self.OFFSET_OPTIONAL_HEADER = header_byte_list[8:12]
            self.PDG_TYPE = header_byte_list[15]
            self.X_PIX = header_byte_list[16:18]
            self.Y_PIX = header_byte_list[18:20]
            self.ColorDepth = header_byte_list[20]
            self.OFFSET_PDG_DATA = header_byte_list[24:28]
            self.SIZE = header_byte_list[28:32]
            self.KEY_DATA = header_byte_list[64:112]
            self.SS_USER_KEY = header_byte_list[104:108]

            self.SIZE = struct.unpack("I", self.SIZE)[0]
            
            x_pix = int(hex(self.X_PIX[1]) + hex(self.X_PIX[0])[2:], 16)
            y_pix = int(hex(self.Y_PIX[1]) + hex(self.Y_PIX[0])[2:], 16)
            
            # 损坏的PDG
            if hex(self.PDG_TYPE) == '0xff':
                self.ERROR = 'BROKEN PDG'
                return
            
            if hex(self.PDG_TYPE) == '0xaa':
                x_pix = 1120
                y_pix = 1568

            # ABH的长宽是反的，需要交换
            if hex(self.PDG_TYPE) == '0xab':
                x_pix, y_pix = y_pix, x_pix
            
            # ACH的加密算法
            if hex(self.PDG_TYPE) == '0xac':
                x_pix = 1120
                y_pix = 1568

            # 0x10型需要解密
            if hex(self.PDG_TYPE) == '0x10':
                x_pix, y_pix = self._xy_decoder()

            self.X_PIX = x_pix
            self.Y_PIX = y_pix

    def _xy_decoder(self):
        """解密10H的长宽"""
        KEY = self.SS_USER_KEY
        X_PIX = self.X_PIX
        Y_PIX = self.Y_PIX
        key_32 = (KEY[3] << 24) + (KEY[2] << 16) + (KEY[1] << 8) + KEY[0]
        cipher_x = (X_PIX[1] << 8) + X_PIX[0]
        cipher_y = (Y_PIX[1] << 8) + Y_PIX[0]
        highword_key_32 = c_uint32(key_32).value & 0xffff0000
        highword_key_32 = highword_key_32 >> 16
        d = (key_32 
             - (highword_key_32 - 219 * (((2510300521 * highword_key_32) >> 32) >> 7)) 
             * (highword_key_32 - 511 * (((2151686161 * highword_key_32) >> 32) >> 8)) 
             + 20718)
        d = d & 0x0000ffff
        c = highword_key_32 - 131 * (((1049152317 * highword_key_32) >> 32) >> 5)
        e = d * highword_key_32
        x_pix_t = c - e - d % 1019 + cipher_x
        y_pix_t = d % 1019 - c - e + cipher_y
        x_pix_plaintext = (x_pix_t & 0xffffffff) & 0x0000ffff
        y_pix_plaintext = (y_pix_t & 0xffffffff) & 0x0000ffff
        return x_pix_plaintext, y_pix_plaintext


def decode_single_pdg(input_file, output_file, dll_path):
    """解码单个PDG文件"""
    try:
        # 解析PDG属性
        pdg = PDG(input_file)
        
        # 判断是否需要解码：文件扩展名是.pdg或者检测到PDG格式
        file_ext = os.path.splitext(input_file)[1].lower()
        need_decode = (file_ext == '.pdg' or pdg.IMG_TYPE == 'pdg')
        
        # 如果是普通图片文件（非.pdg扩展名且检测为图片），直接复制
        if not need_decode and pdg.IMG_TYPE in ['jpeg', 'png', 'bmp', 'tiff', 'gif']:
            from shutil import copyfile
            output_with_ext = output_file + '.' + pdg.IMG_TYPE
            copyfile(input_file, output_with_ext)
            print("[OK] Copy: {} -> {}".format(os.path.basename(input_file), os.path.basename(output_with_ext)))
            return True
        
        # 检查PDG是否损坏
        if pdg.ERROR == 'BROKEN PDG':
            print("[SKIP] Broken PDG: {}".format(os.path.basename(input_file)))
            return False
        
        # 加载DLL
        pdg_dll = CDLL(dll_path)
        
        # 初始化
        pdg_dll.pdgInit()
        
        # 准备参数
        size = c_int(0)
        imgtype = c_int(0)
        img_buffer_ptr = c_ulonglong(0)
        
        input_file_c = input_file + '\0'
        bytes_input_file = bytes(input_file_c, 'utf-8')
        
        # 解码
        pdg_dll.pdgDecode(
            c_char_p(bytes_input_file),
            c_int(pdg.X_PIX),
            c_int(pdg.Y_PIX),
            pointer(img_buffer_ptr),
            pointer(size),
            pointer(imgtype)
        )
        
        # 读取解码后的数据
        img_address = img_buffer_ptr.value
        buf_size = size.value
        img_buffer = create_string_buffer(buf_size)
        memmove(img_buffer, img_address, buf_size)
        output_buffer = img_buffer.raw[0:size.value]
        
        # 检测输出文件类型
        img_type = pdg._detect_file_type(output_buffer[0:34])
        if img_type != 'unknown':
            output_file = output_file + '.' + img_type
        else:
            output_file = output_file + '.bmp'
        
        # 写入文件
        with open(output_file, 'wb') as f:
            f.write(bytes(output_buffer))
        
        # 释放缓冲区
        pdg_dll.pdgFreeBuffer(img_buffer_ptr)
        
        print("[OK] Decode: {} -> {}".format(os.path.basename(input_file), os.path.basename(output_file)))
        return True
        
    except Exception as e:
        print("[ERROR] Failed: {} - {}".format(os.path.basename(input_file), str(e)))
        return False


def pdg_decoder_dll(input_dir, output_dir, dll_path=None):
    """
    批量解码PDG文件
    
    Args:
        input_dir: 输入目录路径
        output_dir: 输出目录路径
        dll_path: PdgView.dll的路径（可选）
    """
    # 检查输入目录
    if not os.path.exists(input_dir):
        print("Error: Input directory not found: {}".format(input_dir))
        return False
    
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    # 查找DLL
    if dll_path is None:
        # 尝试在当前目录和脚本目录查找
        possible_paths = [
            os.path.join(os.getcwd(), "PdgView.dll"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "PdgView.dll"),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                dll_path = path
                break
    
    if dll_path is None or not os.path.exists(dll_path):
        print("Error: PdgView.dll not found")
        print("Please put PdgView.dll in the same directory as this script, or use --dll to specify the path")
        return False
    
    print("Using DLL: {}".format(dll_path))
    print("Input directory: {}".format(input_dir))
    print("Output directory: {}".format(output_dir))
    print("-" * 60)
    
    # 收集所有PDG和图片文件
    supported_extensions = ['.pdg', '.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.gif']
    files_to_process = []
    
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if any(file.lower().endswith(ext) for ext in supported_extensions):
                input_path = os.path.join(root, file)
                # 保持目录结构
                rel_path = os.path.relpath(root, input_dir)
                output_subdir = os.path.join(output_dir, rel_path)
                os.makedirs(output_subdir, exist_ok=True)
                
                output_path = os.path.join(output_subdir, os.path.splitext(file)[0])
                files_to_process.append((input_path, output_path))
    
    if not files_to_process:
        print("Warning: No PDG or image files found")
        return False
    
    # 处理文件
    print("Found {} files".format(len(files_to_process)))
    print("-" * 60)
    
    success_count = 0
    fail_count = 0
    
    for input_path, output_path in files_to_process:
        if decode_single_pdg(input_path, output_path, dll_path):
            success_count += 1
        else:
            fail_count += 1
    
    # 统计结果
    print("-" * 60)
    print("Completed: {} succeeded, {} failed".format(success_count, fail_count))
    
    return True


def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(
        description='PDG Decoder Tool - Batch decode PDG format book files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input_folder
  %(prog)s input_folder output_folder
  %(prog)s input_folder output_folder --dll C:\\path\\to\\PdgView.dll
        """
    )
    
    parser.add_argument('input_dir', help='Input directory path')
    parser.add_argument('output_dir', nargs='?', help='Output directory path (default: input_dir_dll_decrypted)', default=None)
    parser.add_argument('--dll', help='Path to PdgView.dll (optional)', default=None)
    
    args = parser.parse_args()
    
    # 如果没有指定输出目录，使用默认值
    if args.output_dir is None:
        args.output_dir = args.input_dir.rstrip('/\\') + '_dll_decrypted'
    
    # 执行解码
    success = pdg_decoder_dll(args.input_dir, args.output_dir, args.dll)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
