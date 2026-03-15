#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CONFIGURATION="${CONFIGURATION:-Release}"
OUTPUT_DIR="$ROOT_DIR/dist/RemoteRewriteApp"
BUILD_DIR="$ROOT_DIR/bin/$CONFIGURATION"
ZIP_PATH="$ROOT_DIR/dist/RemoteRewriteApp.zip"

if [ -d "$BUILD_DIR/net9.0" ]; then
  BUILD_DIR="$BUILD_DIR/net9.0"
fi

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

dotnet build "$ROOT_DIR/RemoteRewriteApp.csproj" -c "$CONFIGURATION"

cp "$BUILD_DIR/RemoteRewriteApp.dll" "$OUTPUT_DIR/"
cp "$BUILD_DIR/RemoteRewriteApp.pdb" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$BUILD_DIR/RemoteRewriteApp.deps.json" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$ROOT_DIR/dnsApp.config" "$OUTPUT_DIR/"

rm -f "$ZIP_PATH"

if command -v zip >/dev/null 2>&1; then
  (cd "$OUTPUT_DIR" && zip -r "$ZIP_PATH" . >/dev/null)
elif command -v perl >/dev/null 2>&1; then
  OUTPUT_DIR_ENV="$OUTPUT_DIR" ZIP_PATH_ENV="$ZIP_PATH" perl -MIO::Compress::Zip=zip -e '
    use strict;
    use warnings;
    use File::Find;
    my $base = $ENV{OUTPUT_DIR_ENV};
    my $zip_path = $ENV{ZIP_PATH_ENV};
    my @files;
    find(
      sub {
        return if -d $_;
        my $full = $File::Find::name;
        (my $rel = $full) =~ s{^\Q$base/\E}{};
        push @files, [ $full, $rel ];
      },
      $base
    );
    my $zip = IO::Compress::Zip->new($zip_path)
      or die "zip create failed: $IO::Compress::Zip::ZipError\n";
    for my $entry (@files) {
      my ($full, $rel) = @$entry;
      $zip->newStream(Name => $rel)
        or die "zip stream failed for $rel: $IO::Compress::Zip::ZipError\n";
      $zip->print(do {
        local $/;
        open my $fh, "<", $full or die "open $full failed: $!\n";
        binmode $fh;
        <$fh>;
      });
    }
    $zip->close or die "zip close failed: $IO::Compress::Zip::ZipError\n";
  '
else
  printf '%s\n' "zip or perl is required to create $ZIP_PATH" >&2
  exit 1
fi

printf '%s\n' "Created $ZIP_PATH"
