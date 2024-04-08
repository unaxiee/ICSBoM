import subprocess


def binwalk_unpack_fw(firmware, fw_dir, out_dir, log_file, bw_depth=8):
    try:
        ret = subprocess.run([f"binwalk --extract --matryoshka --depth={bw_depth} --log={out_dir}/{log_file} --csv --verbose --directory={out_dir} {firmware}"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             check=False, shell=True, cwd=fw_dir)
        stdout = ret.stdout
        ret.check_returncode()
        return 0
    except subprocess.CalledProcessError:
        print(f"[e] Binwalk error: {str(stdout)}")
        return -1
