import sys
import os
import re
import csv
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

# Add splunklib to sys.path relative to decryption.py's location
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "splunklib"))

@Configuration()
class DecryptionCommand(StreamingCommand):
    charset = Option(require=True)  # Remove charset validation, we will handle it dynamically
    field = Option(require=False, default="_raw")  # Default to _raw if no field is specified

    def load_replacements(self, charset_value):
        # Determine the filename based on charset value
        if charset_value == "utf-8":
            lookup_file = os.path.join(os.path.dirname(__file__), '..', 'lookups', 'utf8replacements.csv')
        elif charset_value == "iso-8859-1":
            lookup_file = os.path.join(os.path.dirname(__file__), '..', 'lookups', 'iso88591replacements.csv')
        elif charset_value == "iso-8859-2":
            lookup_file = os.path.join(os.path.dirname(__file__), '..', 'lookups', 'iso88592replacements.csv')
        elif charset_value == "windows-1252":
            lookup_file = os.path.join(os.path.dirname(__file__), '..', 'lookups', 'windows1252replacements.csv')
        else:
            raise ValueError("Unsupported charset")

        # Load the replacement patterns from the selected lookup file
        replacements = {}
        with open(lookup_file, mode='r') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                replacements[row['hex_pattern'].strip()] = row['replacement'].strip()

        return replacements

    def stream(self, records):
        # Process each record
        for record in records:
            # Check if charset is a field or literal value
            charset_value = record.get(self.charset, self.charset)  # Use the field's value if it exists

            # Load replacements based on charset
            replacements = self.load_replacements(charset_value)

            # Process each record and replace patterns in the specified field
            if self.field in record:
                field_data = record[self.field]
                for hex_pattern, replacement in replacements.items():
                    field_data = re.sub(hex_pattern, replacement, field_data, flags=re.IGNORECASE)
                record[self.field] = field_data

            yield record

if __name__ == "__main__":
    dispatch(DecryptionCommand, sys.argv, sys.stdin, sys.stdout, __name__)

