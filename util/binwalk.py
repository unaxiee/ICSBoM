import subprocess
import shutil
import os
import docker


def is_tool_installed(name):
    """Check if a program is installed and available on PATH"""
    return shutil.which(name) is not None


def is_docker_installed():
    """Check if Docker is installed and available"""
    try:
        client = docker.from_env()
        client.ping()
        return True
    except docker.errors.DockerException as e:
        print(f"[i] Docker connection error: {str(e)}")
        return False
    except Exception as e:
        print(f"[i] Unexpected error when checking Docker: {str(e)}")
        return False


def binwalk_unpack_fw(firmware, fw_dir, out_dir, log_file, bw_depth=8):
    """
    Extract firmware using binwalk, either natively or via Docker.
    This function is designed to work on both Linux and Windows platforms.

    Args:
        firmware: Firmware file name
        fw_dir: Directory containing the firmware
        out_dir: Directory to extract firmware to
        log_file: Log file name
        bw_depth: Binwalk extraction depth

    Returns:
        0 on success, -1 on failure
    """
    # Check if binwalk is installed
    if is_tool_installed("binwalk"):
        try:
            # Normalize paths for cross-platform compatibility
            norm_out_dir = out_dir.replace('\\', '/')
            norm_log_file = log_file.replace('\\', '/')
            norm_firmware = firmware.replace('\\', '/')

            ret = subprocess.run([f"binwalk --extract --matryoshka --depth={bw_depth} --log={norm_out_dir}/{norm_log_file} --csv --verbose --directory={norm_out_dir} {norm_firmware}"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 check=False, shell=True, cwd=fw_dir)
            stdout = ret.stdout
            ret.check_returncode()
            return 0
        except subprocess.CalledProcessError:
            print(f"[e] Binwalk error: {str(stdout)}")
            return -1
    # If binwalk is not installed, check if Docker is installed
    elif is_docker_installed():
        print("[i] Binwalk not found on system. Attempting to use Docker...")
        try:
            # Convert paths to absolute and normalize for cross-platform compatibility
            abs_fw_dir = os.path.normpath(os.path.abspath(fw_dir))
            abs_out_dir = os.path.normpath(os.path.join(abs_fw_dir, out_dir))

            os.makedirs(abs_out_dir, exist_ok=True)

            # if any Windows backslashes then convert forward slashes for Docker
            docker_fw_dir = abs_fw_dir.replace('\\', '/')

            client = docker.from_env()

            # Define binwalk command to run inside the container
            # Ensure paths use forward slashes for the Linux container
            container_out_dir = out_dir.replace('\\', '/')
            container_log_file = log_file.replace('\\', '/')
            container_firmware = firmware.replace('\\', '/')
            binwalk_cmd = f' --extract --matryoshka --depth={bw_depth} --log=/data/{container_out_dir}/{container_log_file} --csv --verbose --directory=/data/{container_out_dir} {container_firmware}'


            # Run the container without detach mode
            container = client.containers.run(
                image="cincan/binwalk",
                command=binwalk_cmd,
                volumes={docker_fw_dir: {'bind': '/data', 'mode': 'rw'}},
                working_dir="/data",
                remove=True,
                detach=False,
                stream=True
            )

            if isinstance(container, bytes):
                output = container.decode('utf-8')
                if 'error' in output.lower() or 'warning' in output.lower():
                    print(f"[e] {output}")
            else:
                for line in container:
                    if isinstance(line, bytes):
                        output = line.decode('utf-8').strip()
                        if 'error' in output.lower() or 'warning' in output.lower():
                            print(f"[e] {output}")

            return 0
        except Exception as e:
            print(f"[e] Docker binwalk error: {str(e)}")
            return -1
    else:
        print("[e] Neither binwalk nor Docker is installed. Cannot proceed with firmware extraction.")
        return -1
