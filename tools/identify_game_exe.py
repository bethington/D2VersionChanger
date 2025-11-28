#!/usr/bin/env python3
"""
Identify Diablo 2 Game.exe version.

Usage: python identify_game_exe.py <path_to_Game.exe>

Identifies the version by:
1. SHA256 hash lookup against known versions (exact match)
2. PE version extraction as fallback (best guess)
"""
import sys
import hashlib
import struct
from pathlib import Path

# Known Game.exe hashes -> (version, game_type, nocd)
# Generated from D2VersionChanger collection
KNOWN_HASHES = {
    # Classic versions - Original
    "d5860c091b5764bbc60ba027ce3cbb18f0a9009de078ed4785cd0cce33824240": ("1.00", "Classic", False),
    "b115fa675290eab1e664bbb7aa469d5701ee75e86765210a2c030c4251a01f22": ("1.01", "Classic", False),
    "ee1dd916a917a43c15361fe2b887aff21c4daf9fd8c8af39e05318b0ab4099d7": ("1.02", "Classic", False),
    "924ffdbdddcc17599b1662bad5d89009ec0d24dd0ceb5347c0bc727c0c56d1f6": ("1.03", "Classic", False),
    "50ff5f0370a8e8632dded10b68f81743330b120a7f2bbf977974a17e4047a97f": ("1.04b", "Classic", False),
    "a00b99dd9fa3e98b38ef0d44988afb4e5781309e2cfcd27e81e438d4f61a2072": ("1.04c", "Classic", False),
    "dcc710132c650231181bc776fda85ddc30928c6c2d38b919132c31e48f7b2a6d": ("1.05", "Classic", False),
    "efda7b5d5d03262aef0b661b1aa753625495b3b28bb2e3f1f13561babdeeb308": ("1.05b", "Classic", False),
    "4712cd26668696d7d01b90b85d55b718601a6eecc95f0c9bab1e16b3f5d6e59c": ("1.06", "Classic", False),
    "cf5647d244f2655ca09778704a0068bd965872adcd504dc43d519550f6ed5c8c": ("1.06b", "Classic", False),
    "ffa78a89636b03ebb8560907688193895d27e6736aad44d0442e3207ba67ad44": ("1.08", "Classic", False),
    "f669ad517f99438067ac8f10fd21939a697776b8a545d7e623d93fd0b1109542": ("1.09", "Classic", False),
    "8671802cb23858d4a6f3bc030d9fc47603372a4c7596e3316748415df5d5cd35": ("1.09b", "Classic", False),
    "8596865ffb58723cfe6e49076b8b1825285433cf240702a1623f22e5f983ca88": ("1.09d", "Classic", False),
    "d8a7bae2cd3e14d72002e88dde9b6db630604e536aa2eff6e2db442cbb033907": ("1.10", "Classic", False),
    "dfd1c61746c17eba0dd3dac206b1695cdbbf9fe22e270c786ee6dd799c4e2a3a": ("1.11", "Classic", False),
    "96746bf46f2893f87ff0655514c54088d0114448bcf884358d818e5c59606f8f": ("1.11b", "Classic", False),
    "3ca642e872dbd9abacb166dca0cbf41c419ed1b1ba48339953117a01d05a270c": ("1.12a", "Classic", False),
    "4d863b672f3e16fce6dd4e5ee795f4429195db2635c4eacbef37f435b69feb5d": ("1.13c", "Classic", False),
    "9622ca993de5f5738ad437cc9c4b75ad35e439ec9aaff6a3501870861a5a0ef1": ("1.13d", "Classic", False),
    "306812bf7f37e21fecb77d11e23f28005c97eeb2c7dd666b1352c2bb1de87cb5": ("1.14a", "Classic", False),
    "28fac184096fc36a37c5126590e65e71a3c9569c18b9000357fd7613a56b8c3c": ("1.14b", "Classic", False),
    "6c7b8dfbb4092ec38066f2660d7e065e44e94d80258265a46201e1af073a3173": ("1.14c", "Classic", False),
    "cbe413edb4af9495db06d489715922d4dcdd77a91701cef089a6b2979d453bbd": ("1.14d", "Classic", False),
    # Classic versions - NoCD
    "a561dfdbc8ff660e83fd1c74a651e5081731faed4ad324799756cf04312b35b9": ("1.00", "Classic", True),
    "cc9e64d0cac0e667b7f361b62080d7f2ae33c1360e73256aa123fffb4e7a3da0": ("1.01", "Classic", True),
    "8555607bfb9a2ed5a0772499b27326db12ee8125254eff6da826df2aa07a248c": ("1.02", "Classic", True),
    "7f5f17f15dd99baccb90d5e51ef9dd4745a2682a0a16a509007df0167fcb2bb4": ("1.03", "Classic", True),
    "98157b1eaafc10433d3cf7b47e5cac5b8755709c18a8a8f89fdbc3c57a31216c": ("1.04b", "Classic", True),
    "51550c0868c7c487b40c833bd3548371819d2e370147aaad639fa10dcadfd4a1": ("1.04c", "Classic", True),
    "ada3888c879a2ee4baff8c26857f805bdfdbbabcf31e33d0fcf283f14eac0489": ("1.05", "Classic", True),
    "5d1453b20da87a46ab65a6482b6081255e80c010adc926c44b730b641790e704": ("1.05b", "Classic", True),
    "9bc2fceff33a40a459e0e95cc284e812342f2701a6051fff93f8256a96a03307": ("1.06", "Classic", True),
    "b1984c34b4d9d55e19a9f92cfea5ec85e54d3f310d2c620ad7ec4bb8b302b4b6": ("1.06b", "Classic", True),
    "4be57fb2060a7d515de3f0a26dcf58f23eb153fa23fb2135b6174865b281318b": ("1.08", "Classic", True),
    "ddd3dc2557a5cfcbb58d7aea958584030cb4716c8d8a8d2f8cfea4a0adcf5429": ("1.09", "Classic", True),
    "256f6aa82f02e155373d885337a3a5060ac21e7e3b8bf49a1d7be9299fbdf2ed": ("1.09b", "Classic", True),
    "02db9652b98a280067a5aff445b5acc835e07b54019a5669dc01ca6189b6c658": ("1.09d", "Classic", True),
    "5a17de09dffb03c6b72f2bd16f26e45e73f433232026ba898ab7b7c02722c627": ("1.10", "Classic", True),
    "ec4e10073875d5f0214576b4afbdf9d5deb497cbded9dced20196b8cd1d299c2": ("1.11", "Classic", True),
    "0ac37d81aebb1468bf42a2c16b0b8e15b10ec60db146fa43b833644c6937921e": ("1.11b", "Classic", True),
    # LoD versions - Original
    "dd899789710b768682cb063854932510c6116b503a829fe0632cfd5383e579e6": ("1.07", "LoD", False),
    "ee2dff122fd2b373ae8cff38ed48ddbd9032ddad916a5d0a93f2b40f8e7b9217": ("1.08", "LoD", False),
    "4daeec8a5659eba41caf90837a4c62ee996289e7291fd82fe2f993c07c18b942": ("1.09", "LoD", False),
    "add36ecb630a3b7cd73700bc22298f340ce9999ba97bf172e9a034459fb44a88": ("1.09b", "LoD", False),
    "b211b8ad79e9f2bbb29f6e7b0d861cadbd1fe63438a12d740f01404fd2ce8df6": ("1.09d", "LoD", False),
    "5bfa2d47d8d5521d8e6aafe46fe6d331bf6ee4d1cbdb42d2d39c7fa682ca825f": ("1.10", "LoD", False),
    "517a0ce7ea79444aa2290249b34f7402c5e81da767882c2286c548756b1c92c7": ("1.10 Beta 1", "LoD", False),
    "8cc53aa120d135fd0eaaabcb1500c1773d95b93e64fb6477ade333e4eb819c94": ("1.10 Beta 2", "LoD", False),
    "45fdb5a87fc37c52103c56a0aa701c4f6c8b31de0721ad535fe07e5958f5a962": ("1.11", "LoD", False),
    "821fb4fb617b440403a1e2b576139386f381369046e39dbe9be4458a2439c952": ("1.11b", "LoD", False),
    "9cb3d8dd0ffac92c164ba2a29f358d17fb372380abdcc15f871831f262de09fa": ("1.12a", "LoD", False),
    "74fe9c092a521f7710392548c82f81544e531107db2358617e83818874db40a2": ("1.13c", "LoD", False),
    "6ca6f345c11f47eaf6dc629457ec2ea0020fa7fba4aa9bb2248f911b66870ddd": ("1.13d", "LoD", False),
    "c99e3067e6a7eef7800680ac6bed2beb1a50cc285933166bcd7fbe4f394446a6": ("1.14a", "LoD", False),
    "0680e266b1fbbc8e7815b0a7c4f67267de38fd9063fceeae2da0306389a52178": ("1.14b", "LoD", False),
    "ad13296ae56b921987f1088e22d01d4edd4a56c0bd15af186549de87a03af29c": ("1.14c", "LoD", False),
    "631066c1649c4ea9ffe48bf97e24c00bca1f7a6759c21150f1a79982589adaaf": ("1.14d", "LoD", False),
    # LoD versions - NoCD
    "8b07fc9963acfee35c09b8688deab4598543d975bbd994872a6eca6c9160344a": ("1.07", "LoD", True),
    "118e0d420e31a5f9bc3dfbf1387d62b3e1c9522a3087ff1702d6f5c2519000b9": ("1.08", "LoD", True),
    "a14b150fad042aef91ee866e9991edd1f5d7dae35213c90a236a950b8f95ce9e": ("1.09", "LoD", True),
    "a162053932d2577e3d9664c76939481e67e452f92e9177605a6f3418e7fc29f9": ("1.09b", "LoD", True),
    "2b7391519396228f4f7f902426c67157f35fbeef95c9e1f64014d8f70554e182": ("1.09d", "LoD", True),
    "1ea46ed66d3b9c12965edf13b6d8141cf570249d53991ecadab4892ed8f99ea9": ("1.10", "LoD", True),
    "c982e3944c985c9b02e72b6a06fb14b30c3065cfc7cc22dadf23c379e131e5f7": ("1.10 Beta 1", "LoD", True),
    "81505e72228a34969b27db497e6da3a90231bacce0e1912e040df953bc9c1d83": ("1.10 Beta 2", "LoD", True),
    "01437ce204849ad7275d15993fcdc1b16bb0ba299b458579611670ffebc0e8dc": ("1.11", "LoD", True),
    "376129a5a15ad7017fcc3f0473e75e43f4b368d50089a487b02d6a9e49dad105": ("1.11b", "LoD", True),
}

# PE version -> version string mapping for fallback
PE_VERSION_MAP = {
    (1, 0, 0, 1): "1.00",
    (1, 0, 2, 0): "1.02",
    (1, 0, 3, 0): "1.03",
    (1, 0, 4, 1): "1.04b",
    (1, 0, 4, 2): "1.04c",
    (1, 0, 5, 0): "1.05",
    (1, 0, 5, 1): "1.05b",
    (1, 0, 6, 0): "1.06/1.06b",
    (1, 0, 7, 0): "1.07",
    (1, 0, 8, 28): "1.08",
    (1, 0, 9, 19): "1.09",
    (1, 0, 9, 20): "1.09b",
    (1, 0, 9, 22): "1.09d",
    (1, 0, 10, 9): "1.10 Beta 1",
    (1, 0, 10, 10): "1.10 Beta 2",
    (1, 0, 10, 39): "1.10",
    (1, 0, 11, 45): "1.11",
    (1, 0, 11, 46): "1.11b",
    (1, 0, 12, 49): "1.12a",
    (1, 0, 13, 60): "1.13c",
    (1, 0, 13, 64): "1.13d",
    (1, 14, 0, 64): "1.14a",
    (1, 14, 1, 68): "1.14b",
    (1, 14, 2, 70): "1.14c",
    (1, 14, 3, 71): "1.14d",
}


def get_sha256(filepath: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def extract_pe_version(filepath: Path) -> tuple:
    """
    Extract version info from PE file header.
    Returns tuple of (major, minor, build, revision) or None.
    """
    try:
        with open(filepath, 'rb') as f:
            # Check DOS header
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                return None
            
            # Get PE header offset
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            f.seek(pe_offset)
            
            # Verify PE signature
            pe_sig = f.read(4)
            if pe_sig != b'PE\x00\x00':
                return None
            
            # Read COFF header
            coff_header = f.read(20)
            size_of_optional = struct.unpack('<H', coff_header[16:18])[0]
            
            if size_of_optional == 0:
                return None
            
            # Read optional header
            optional_header = f.read(size_of_optional)
            
            # Check PE32 vs PE32+
            magic = struct.unpack('<H', optional_header[:2])[0]
            if magic == 0x10b:  # PE32
                num_data_dirs = struct.unpack('<I', optional_header[92:96])[0]
                data_dir_offset = 96
            elif magic == 0x20b:  # PE32+
                num_data_dirs = struct.unpack('<I', optional_header[108:112])[0]
                data_dir_offset = 112
            else:
                return None
            
            if num_data_dirs < 3:
                return None
            
            # Get resource directory RVA
            resource_rva = struct.unpack('<I', optional_header[data_dir_offset + 16:data_dir_offset + 20])[0]
            
            if resource_rva == 0:
                return None
            
            # Read section headers to find resource section
            f.seek(pe_offset + 24 + size_of_optional)
            num_sections = struct.unpack('<H', coff_header[2:4])[0]
            
            resource_offset = None
            for _ in range(num_sections):
                section = f.read(40)
                section_rva = struct.unpack('<I', section[12:16])[0]
                section_size = struct.unpack('<I', section[16:20])[0]
                raw_offset = struct.unpack('<I', section[20:24])[0]
                
                if section_rva <= resource_rva < section_rva + section_size:
                    resource_offset = raw_offset + (resource_rva - section_rva)
                    break
            
            if resource_offset is None:
                return None
            
            # Search for VS_VERSION_INFO
            f.seek(resource_offset)
            resource_data = f.read(65536)  # Read up to 64KB of resource section
            
            # Look for VS_FIXEDFILEINFO signature (0xFEEF04BD)
            sig = b'\xbd\x04\xef\xfe'
            pos = resource_data.find(sig)
            
            if pos == -1:
                return None
            
            # Parse VS_FIXEDFILEINFO
            ffi = resource_data[pos:pos + 52]
            if len(ffi) < 52:
                return None
            
            file_version_ms = struct.unpack('<I', ffi[8:12])[0]
            file_version_ls = struct.unpack('<I', ffi[12:16])[0]
            
            major = (file_version_ms >> 16) & 0xFFFF
            minor = file_version_ms & 0xFFFF
            build = (file_version_ls >> 16) & 0xFFFF
            revision = file_version_ls & 0xFFFF
            
            return (major, minor, build, revision)
            
    except Exception:
        return None


def identify_game_exe(filepath: Path) -> dict:
    """
    Identify a Diablo 2 Game.exe file.
    
    Returns dict with:
        - method: 'hash' or 'pe_version'
        - version: version string
        - game_type: 'Classic', 'LoD', or 'Unknown'
        - nocd: True/False/None
        - hash: SHA256 hash
        - pe_version: tuple or None
        - confidence: 'exact' or 'approximate'
    """
    result = {
        'filepath': str(filepath),
        'method': None,
        'version': None,
        'game_type': 'Unknown',
        'nocd': None,
        'hash': None,
        'pe_version': None,
        'pe_version_raw': None,
        'confidence': None,
    }
    
    if not filepath.exists():
        result['error'] = 'File not found'
        return result
    
    # Get hash
    file_hash = get_sha256(filepath)
    result['hash'] = file_hash
    
    # Try hash lookup first
    if file_hash in KNOWN_HASHES:
        version, game_type, nocd = KNOWN_HASHES[file_hash]
        result['method'] = 'hash'
        result['version'] = version
        result['game_type'] = game_type
        result['nocd'] = nocd
        result['confidence'] = 'exact'
    
    # Get PE version
    pe_ver = extract_pe_version(filepath)
    if pe_ver:
        result['pe_version'] = pe_ver
        result['pe_version_raw'] = f"{pe_ver[0]}, {pe_ver[1]}, {pe_ver[2]}, {pe_ver[3]}"
        
        # If hash didn't match, use PE version as fallback
        if result['method'] is None:
            if pe_ver in PE_VERSION_MAP:
                result['method'] = 'pe_version'
                result['version'] = PE_VERSION_MAP[pe_ver]
                result['confidence'] = 'approximate'
                
                # Guess game type based on file size (LoD 1.14+ is larger)
                file_size = filepath.stat().st_size
                if pe_ver[1] >= 14:  # 1.14+
                    result['game_type'] = 'LoD' if file_size > 3500000 else 'Classic'
                else:
                    result['game_type'] = 'Unknown (could be Classic or LoD)'
            else:
                result['method'] = 'pe_version'
                result['version'] = f"Unknown (PE: {pe_ver[0]}.{pe_ver[1]}.{pe_ver[2]}.{pe_ver[3]})"
                result['confidence'] = 'unknown'
    
    if result['method'] is None:
        result['error'] = 'Could not identify version'
    
    return result


def main():
    if len(sys.argv) < 2:
        # Default to Game.exe in the same folder as this script
        script_dir = Path(__file__).parent
        filepath = script_dir / "Game.exe"
        if not filepath.exists():
            print("Usage: python identify_game_exe.py [path_to_Game.exe]")
            print("\nIf no path is provided, looks for Game.exe in the same folder as this script.")
            print(f"\nNo Game.exe found at: {filepath}")
            sys.exit(1)
    else:
        filepath = Path(sys.argv[1])
    
    result = identify_game_exe(filepath)
    
    print(f"\n{'=' * 60}")
    print(f"Diablo 2 Game.exe Identifier")
    print(f"{'=' * 60}")
    print(f"File: {result['filepath']}")
    print(f"SHA256: {result['hash']}")
    print(f"PE Version: {result.get('pe_version_raw', 'Unable to extract')}")
    
    print(f"\n{'─' * 60}")
    
    if result.get('error'):
        print(f"Error: {result['error']}")
    else:
        print(f"Version: {result['version']}")
        print(f"Game Type: {result['game_type']}")
        if result['nocd'] is not None:
            print(f"NoCD Patch: {'Yes' if result['nocd'] else 'No'}")
        print(f"Detection Method: {result['method']}")
        print(f"Confidence: {result['confidence']}")
    
    print(f"{'=' * 60}\n")
    
    return 0 if result.get('version') else 1


if __name__ == '__main__':
    sys.exit(main())
