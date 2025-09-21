import os

def merge_python_files():
    folder_path = os.getcwd()  # get the present folder automatically
    folder_name = os.path.basename(os.path.normpath(folder_path))
    output_file = f"{folder_name}.txt"

    with open(output_file, "w", encoding="utf-8") as outfile:
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(".py") and file != __file__:  # avoid copying this script itself
                    file_path = os.path.join(root, file)
                    outfile.write(f"\n\n=== File: {file_path} ===\n\n")
                    try:
                        with open(file_path, "r", encoding="utf-8") as infile:
                            outfile.write(infile.read())
                    except Exception as e:
                        outfile.write(f"\n[Error reading {file_path}: {e}]\n")

    print(f"✅ All Python files merged into: {output_file}")


if __name__ == "__main__":
    merge_python_files()
