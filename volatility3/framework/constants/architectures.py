def _intel():
    from volatility3.framework.layers import intel
    return intel.Intel

def _aarch64():
    from volatility3.framework.layers import arm
    return arm.AArch64

WIN_ARCHS = ["Intel32", "Intel64"]
"""Windows supported architectures"""
WIN_ARCHS_LAYERS = [_intel()]
"""Windows supported architectures layers"""

LINUX_ARCHS = ["Intel32", "Intel64", "AArch64"]
"""Linux supported architectures"""
LINUX_ARCHS_LAYERS = [_intel(), _aarch64()]
"""Linux supported architectures layers"""

MAC_ARCHS = ["Intel32", "Intel64"]
"""Mac supported architectures"""
MAC_ARCHS_LAYERS = [_intel()]
"""Mac supported architectures layers"""

FRAMEWORK_ARCHS = ["Intel32", "Intel64"]
"""Framework supported architectures"""
FRAMEWORK_ARCHS_LAYERS = [_intel()]
"""Framework supported architectures layers"""