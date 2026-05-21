import sys
import traceback

try:
    from analyzer import AppAnalyzer
    print("Import successful!")
except Exception as e:
    print("Error during import:")
    traceback.print_exc()
