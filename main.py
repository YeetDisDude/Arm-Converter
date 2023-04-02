import os, subprocess

modules = [
    ("dearpygui", "import dearpygui.dearpygui as dpg"),
    ("httpx", "import httpx"),
    ("keystone-engine", "from keystone import *"),
    ("capstone", "from capstone import *")
]

needed = []
for module, import_string in modules:
    try:
        exec(import_string)
    except ImportError:
        needed.append(module)

if len(needed) != 0:
    count = 0
    for module in needed:
        count += 1
        print(f"[i] Installing Required Modules... | {count} / {len(needed)}")
        subprocess.check_call(["pip3", "install", module, "-q"])

import dearpygui.dearpygui as dpg
import httpx
from keystone import *
import tkinter as tk
from capstone import *

filepath = os.path.abspath(__file__)
filename = os.path.basename(__file__)
folderpath = os.getcwd()

VERSION = "0.1.0"
UPDATE_URL = "https://raw.githubusercontent.com/YeetDisDude/Cpp2IL-gui/main/version.txt"

def check_update():
    dpg.set_value(f"updatetxt", "Update Status: Checking for updates...")
    r = httpx.get(UPDATE_URL)
    if r.text.strip() != VERSION:
        dpg.set_value("updatetxt", f"Update Status: Version {VERSION} is Outdated! Download the latest version from github.com/YeetDisDude/Arm-Converter")
    else:
        dpg.set_value(f"updatetxt", f"Update Status: Arm Converter version {VERSION} is up to date!")


def armtohex64error(e):
        if e.errno == KS_ERR_ASM_MNEMONICFAIL:
            arm64hex = "Invalid Mnemonic"
            dpg.set_value("armtohexarm64", arm64hex)
        elif e.errno == KS_ERR_ASM_INVALIDOPERAND:
            arm64hex = "Invalid Operand"
            dpg.set_value("armtohexarm64", arm64hex)
        else:
            arm64hex = "Assembly Error"
            dpg.set_value("armtohexarm64", arm64hex)

def armtohex7error(e):
        if e.errno == KS_ERR_ASM_MNEMONICFAIL:
            armv7hex = "Invalid Mnemonic"
            dpg.set_value("armtohexarmv7", armv7hex)
        elif e.errno == KS_ERR_ASM_INVALIDOPERAND:
            armv7hex = "Invalid Operand"
            dpg.set_value("armtohexarmv7", armv7hex)
        else:
            armv7hex = "Assembly Error"
            dpg.set_value("armtohexarmv7", armv7hex)

def ArmToHex(sender, data):
    print(data)
    ksarm64 = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    ksarmv7 = Ks(KS_ARCH_ARM, KS_MODE_ARM)
    try:
        bytecode_arm64, _ = ksarm64.asm(data)
        arm64hex = ' '.join('{:02x}'.format(x) for x in bytecode_arm64)
        arm64hex = arm64hex.upper()
        dpg.set_value("armtohexarm64", arm64hex)
    except KsError as e:
        armtohex64error(e=e)

    try:
        bytecode_v7, _ = ksarmv7.asm(data)
        armv7hex = ' '.join('{:02x}'.format(x) for x in bytecode_v7)
        armv7hex = armv7hex.upper()
        dpg.set_value("armtohexarmv7", armv7hex)
    except KsError as e:
        armtohex7error(e=e)

def HexToArm(sender, data):
    data = data.upper()
    print(data)
    csarm64 = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    csarmv7 = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    try:
        for insn in csarm64.disasm(bytes.fromhex(data), 0):
            dpg.set_value("hextoarm64", f"{insn.mnemonic} {insn.op_str}")
        for insn in csarmv7.disasm(bytes.fromhex(data), 0):
            dpg.set_value("hextoarmv7", f"{insn.mnemonic} {insn.op_str}")
    except ValueError as e:
        dpg.set_value("hextoarmv7", "Invalid Hex")
        dpg.set_value("hextoarm64", "Invalid Hex")




def tab1(): # Arm to Hex
    with dpg.group():
        dpg.bind_font(default_font)
        dpg.add_text(" ")
        dpg.add_text("Assembly Code")
        dpg.add_input_text(multiline=True, width=450, height=150, tag="armtohexinput", callback=ArmToHex)
        dpg.add_text(" "); dpg.add_separator(); dpg.add_text(" ")
        dpg.add_input_text(label="Arm64", multiline=True, width=450, height=150, readonly=True, tag="armtohexarm64")
        dpg.add_text(" "); dpg.add_separator(); dpg.add_text(" ")
        dpg.add_input_text(label="Armv7", multiline=True, width=450, height=150, readonly=True, tag="armtohexarmv7")
        dpg.add_text(" "); dpg.add_text(" "); dpg.add_text(" "); dpg.add_text(" "); dpg.add_text(" "); dpg.add_text(" ")


def tab2(): # Hex to Arm
    with dpg.group():
        dpg.add_text(" ")
        dpg.add_text("Hex code")
        dpg.add_input_text(multiline=True, width=450, height=150, tag="hextoarminput", callback=HexToArm, uppercase=True)
        dpg.add_text(" "); dpg.add_separator(); dpg.add_text(" ")
        dpg.add_input_text(label="Arm64", multiline=True, width=450, height=150, readonly=True, tag="hextoarm64")
        dpg.add_text(" "); dpg.add_separator(); dpg.add_text(" ")
        dpg.add_input_text(label="Armv7", multiline=True, width=450, height=150, readonly=True, tag="hextoarmv7")
        dpg.add_text(" "); dpg.add_text(" "); dpg.add_text(" "); dpg.add_text(" "); dpg.add_text(" "); dpg.add_text(" ")
            

def tabsetting(): # settings
    with dpg.group():
        dpg.add_text(" ")
        dpg.add_button(label="Check update", callback=check_update, width=150, height=50)
        dpg.add_text("Update Status: idle", tag="updatetxt")
        dpg.add_text(" ")

imguiW = 800
imguiH = 500


dpg.create_context()
dpg.create_viewport()
dpg.setup_dearpygui()
dpg.set_viewport_small_icon("Assets/Icon.ico")
dpg.set_viewport_large_icon("Assets/Icon.ico")
dpg.set_viewport_title("Arm Converter")
dpg.set_viewport_width(imguiW + 16)
dpg.set_viewport_height(imguiH + 38)





with dpg.font_registry():
    default_font = dpg.add_font("Assets/SF Pro Display Semibold.ttf", 20)

with dpg.window(width=imguiW, height=imguiH, no_resize=False, label=f"Arm Converter | Made by: YeetDisDude#0001 | Version {VERSION}", tag="mainW") as window:
    with dpg.tab_bar():
        with dpg.tab(label="  Assembly to Hex  "):
            tab1()
        with dpg.tab(label="  Hex to Assembly  "):
            tab2()
        with dpg.tab(label="  Settings  "):
            tabsetting()


dpg.show_viewport()
dpg.start_dearpygui()
dpg.destroy_context()