import os
import struct
from datetime import datetime

from utils.output import section, info, success, warning, error, result


def extract_exif(image_path):
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS

        img = Image.open(image_path)
        exif_data = img._getexif()
        if not exif_data:
            return {}

        decoded = {}
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            decoded[tag_name] = value
        return decoded
    except ImportError:
        return None
    except Exception as e:
        return {"error": str(e)}


def extract_pdf_metadata(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        text = data.decode("latin-1")
        meta = {}
        for line in text.split("\n"):
            for prefix in ["/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer", "/CreationDate"]:
                if line.strip().startswith(prefix):
                    parts = line.split("(", 1)
                    if len(parts) > 1:
                        val = parts[1].rsplit(")", 1)[0]
                        meta[prefix] = val
        return meta
    except:
        return {}


def extract_generic_metadata(filepath):
    stat = os.stat(filepath)
    size = stat.st_size
    created = stat.st_ctime
    modified = stat.st_mtime
    return {
        "Size": f"{size:,} bytes",
        "Created": datetime.fromtimestamp(created).strftime("%Y-%m-%d %H:%M:%S"),
        "Modified": datetime.fromtimestamp(modified).strftime("%Y-%m-%d %H:%M:%S"),
        "Permissions": oct(stat.st_mode & 0o777),
    }


class MetadataExtractor:
    name = "metadata"
    description = "Extract metadata from files (images, PDFs, documents)"

    @staticmethod
    def run(target):
        section(f"Metadata Extractor: {target}")

        if not os.path.exists(target):
            error(f"File not found: {target}")
            return {"target": target, "error": "File not found"}

        if os.path.isdir(target):
            info(f"Scanning directory: {target}")
            all_files = []
            for root, dirs, files in os.walk(target):
                for f in files:
                    fpath = os.path.join(root, f)
                    all_files.append(fpath)
            info(f"Found {len(all_files)} file(s)")

            for fpath in all_files:
                print(f"\n{'='*50}")
                result("File", os.path.basename(fpath))
                print(f"{'='*50}")
                results = MetadataExtractor._process_file(fpath)
                if results:
                    for key, val in results.items():
                        if val and val != "N/A":
                            result(key, val)

        else:
            MetadataExtractor._process_file_and_display(target)

        return {"target": target}

    @staticmethod
    def _process_file_and_display(filepath):
        results = MetadataExtractor._process_file(filepath)
        if results:
            for key, val in results.items():
                if val and val != "N/A":
                    result(key, val)

    @staticmethod
    def _process_file(filepath):
        ext = os.path.splitext(filepath)[1].lower()
        meta = extract_generic_metadata(filepath)
        result("File", os.path.basename(filepath))

        if ext in [".jpg", ".jpeg", ".tiff", ".tif", ".png", ".webp"]:
            info("Image EXIF data:")
            exif = extract_exif(filepath)
            if exif is None:
                warning("PIL/Pillow not installed. Install with: pip install Pillow")
            elif exif:
                interesting = [
                    "Make", "Model", "DateTimeOriginal", "DateTimeDigitized",
                    "GPSInfo", "Software", "Artist", "Copyright", "ImageDescription",
                    "Orientation", "XResolution", "YResolution", "FocalLength",
                    "FNumber", "ISOSpeedRatings", "ExposureTime",
                ]
                for tag in interesting:
                    if tag in exif:
                        result(f"  {tag}", str(exif[tag])[:200])
                for k, v in exif.items():
                    if k not in interesting and isinstance(v, (str, int, float)):
                        result(f"  {k}", str(v)[:100])
            else:
                info("  No EXIF data found")

        elif ext == ".pdf":
            info("PDF Metadata:")
            pdf_meta = extract_pdf_metadata(filepath)
            if pdf_meta:
                for k, v in pdf_meta.items():
                    result(f"  {k.lstrip('/')}", v)
            else:
                info("  No metadata found in PDF")

        else:
            info("Generic file info:")
            for k, v in meta.items():
                result(f"  {k}", v)

        return meta
