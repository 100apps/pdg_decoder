#!/usr/bin/env python

# -*- coding: utf-8 -*-

"""

Standalone PDG Decoder using DLL

Combines all PDG decoding logic into a single file

"""


import os

import sys

import ctypes

from ctypes import *

from pathlib import Path


def _parse_jpeg_size_ida_logic(buf):
    """

    Python translation of PdgView.dll::sub_180002AD0.

    Return (width, height) when SOF marker is found, otherwise None.

    """

    size = len(buf)

    if size < 2:

        return None

    if buf[0] != 0xFF or buf[1] != 0xD8:

        return None

    i = 2

    non_ff_count = 0

    sof_markers = {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }

    while i < size:

        if buf[i] != 0xFF:

            non_ff_count += 1

            i += 1

            continue

        i += 1

        while i < size:

            marker = buf[i]

            i += 1

            if marker == 0xFF:

                continue

            if non_ff_count != 0:

                return None

            if marker in (0xD9, 0xDA):

                return None

            if marker in sof_markers:

                # segment length(2) + precision(1) + height(2) + width(2)

                if i + 6 > size:

                    return None

                height = (buf[i + 3] << 8) | buf[i + 4]

                width = (buf[i + 5] << 8) | buf[i + 6]

                return width, height

            if i + 1 >= size:

                return None

            seg_len = (buf[i] << 8) | buf[i + 1]

            if seg_len < 2:

                return None

            i += seg_len

            break

    return None


def file_type_decoder(buf):
    """简单的文件类型检测"""

    if buf.startswith(b"\xff\xd8\xff"):

        return "jpeg"

    elif buf.startswith(b"\x89PNG"):

        return "png"

    elif buf.startswith(b"GIF8"):

        return "gif"

    elif buf.startswith(b"BM"):

        return "bmp"

    elif buf.startswith(b"II*\x00") or buf.startswith(b"MM\x00*"):

        return "tiff"

    return None


def pdg_decode_dll(input_file, x_pix, y_pix, dll_path):
    """

    使用DLL解密PDG文件

    """

    size = c_int(0)

    imgtype = c_int(0)

    img_buffer_ptr = c_ulonglong(0)

    pdg_dll = CDLL(dll_path)

    pdg_dll.pdgInit()

    input_file_c = input_file + "\0"

    bytes_input_file = bytes(input_file_c, "utf-8")

    ret = pdg_dll.pdgDecode(
        c_char_p(bytes_input_file),
        c_int(x_pix),
        c_int(y_pix),
        pointer(img_buffer_ptr),
        pointer(size),
        pointer(imgtype),
    )

    if ret != 0:

        raise RuntimeError(f"pdgDecode failed with code={ret}")

    img_address = img_buffer_ptr.value

    buf_size = size.value

    img_buffer = ctypes.create_string_buffer(buf_size)

    ctypes.memmove(img_buffer, img_address, buf_size)

    output_buffer = img_buffer.raw[0:buf_size]

    jpeg_size = _parse_jpeg_size_ida_logic(output_buffer)

    is_jpeg_match = jpeg_size == (x_pix, y_pix)

    resolved_type = "jpeg" if is_jpeg_match else file_type_decoder(output_buffer[0:34])

    pdg_dll.pdgFreeBuffer(img_buffer_ptr)

    return output_buffer, resolved_type


def pdg_decoder_dll(input_dir, output_dir):
    """

    解密PDG文件夹中的所有PDG文件



    :param input_dir: 输入文件夹路径，包含PDG文件

    :param output_dir: 输出文件夹路径

    :return: 处理的文件数量

    """

    input_path = Path(input_dir)

    output_path = Path(output_dir)

    # 检查输入文件夹是否存在

    if not input_path.exists():

        print(f"错误: 输入文件夹不存在: {input_dir}")

        return 0

    # 创建输出文件夹

    output_path.mkdir(parents=True, exist_ok=True)

    # 查找DLL文件

    dll_path = Path(__file__).parent / "PdgView.dll"

    if not dll_path.exists():

        print(f"错误: 找不到 PdgView.dll 文件: {dll_path}")

        return 0

    # 查找所有PDG文件

    pdg_files = list(input_path.glob("*.pdg"))

    if not pdg_files:

        print(f"警告: 在 {input_dir} 中没有找到PDG文件")

        return 0

    print(f"找到 {len(pdg_files)} 个PDG文件")

    processed_count = 0

    failed_count = 0

    for pdg_file in pdg_files:

        try:

            # 读取PDG文件头获取尺寸信息

            with open(pdg_file, "rb") as f:

                raw_data = f.read(140)

            # 从文件头读取尺寸

            if len(raw_data) >= 140 and raw_data[0:2] == b"HH":

                x_pix = raw_data[16] | (raw_data[17] << 8)

                y_pix = raw_data[18] | (raw_data[19] << 8)

            else:

                # 默认尺寸

                x_pix = 800

                y_pix = 1200

                print(
                    f"  警告: {pdg_file.name} 无法读取尺寸，使用默认值 {x_pix}x{y_pix}"
                )

            # 使用DLL解密PDG文件

            output_buffer, img_type = pdg_decode_dll(
                str(pdg_file), x_pix, y_pix, str(dll_path)
            )

            # 确定输出文件名和扩展名

            filename = pdg_file.stem

            if img_type is not None:

                output_file = output_path / f"{filename}.{img_type}"

            else:

                output_file = output_path / f"{filename}.bin"

            # 写入输出文件

            with open(output_file, "wb") as f:

                f.write(output_buffer)

            print(
                f"  [OK] {pdg_file.name} -> {output_file.name} ({img_type or 'unknown'})"
            )

            processed_count += 1

        except Exception as e:

            print(f"  [FAIL] {pdg_file.name} 处理失败: {str(e)}")

            failed_count += 1

    print(f"\n处理完成: {processed_count} 成功, {failed_count} 失败")

    return processed_count


if __name__ == "__main__":

    if len(sys.argv) < 2:

        print("用法: python pdg_decoder_standalone.py <输入文件夹> [输出文件夹]")

        print("  如果不指定输出文件夹，默认为: <输入文件夹>_dll_decrypted")

        sys.exit(1)

    input_dir = sys.argv[1]

    # 如果没有指定输出文件夹，使用默认值

    if len(sys.argv) >= 3:

        output_dir = sys.argv[2]

    else:

        output_dir = input_dir.rstrip("/\\") + "_dll_decrypted"

    pdg_decoder_dll(input_dir, output_dir)
