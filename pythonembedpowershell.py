import subprocess

def run_powershell_script():
    # Your PowerShell script content embedded as a multi-line string
    powershell_script = '''
    Write-Host "Hello from embedded PowerShell script"
    # You can add more PowerShell commands here
    '''

    # Run the PowerShell script without writing it to a file
    result = subprocess.run(["powershell", "-Command", powershell_script], capture_output=True, text=True)

    # Print the output and any errors
    print(result.stdout)
    if result.stderr:
        print("Error:", result.stderr)

if __name__ == "__main__":
    run_powershell_script()
