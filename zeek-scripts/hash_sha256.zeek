##! Perform SHA256 hashing on all files.
@load base/files/hash
event file_new(f: fa_file)
    {
    Files::add_analyzer(f, Files::ANALYZER_SHA256);
    }