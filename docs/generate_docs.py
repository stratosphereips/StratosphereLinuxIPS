import os
docs = 'docs/'
own_name = os.path.basename(__file__)
doxygen_repo_dirname = 'doxygen-awesome-css'

def delete_all_files(dir_to_clear):
    """
    This function deletes all files and subfiles of a given dir
    excpet for the doxygen repo we use to generate the docs and this python script
    """

    for path, subdirs, files in os.walk(dir_to_clear):
        if doxygen_repo_dirname in path:
            continue
        for file in files:
            if own_name in file:
                continue
            to_delete = os.path.join(path, file)
            os.remove(to_delete)
            print(f"deleted {to_delete}")

    # now all files are deleted, delete the empty dirs in the dir_to_clear
    subfolders = [f.path for f in os.scandir(dir_to_clear) if os.path.isdir(f)]
    for dir in subfolders:
        if doxygen_repo_dirname in dir:
            continue
        os.rmdir(dir)


def regenrate_docs():
    """
    runs 'doxygen' inside doxygen-awesome-css
    docs are generated in docs/html
    """
    # go to teh doxygen css dir
    cur_dir = os.getcwd()
    os.chdir(os.path.join(docs, doxygen_repo_dirname))
    os.system(f"doxygen")
    os.chdir(cur_dir)

def move_html_files_to_docs_dir():
    """
    GH pages are hosted from docs/ dir
    this function moves all the generated docs from docs/html to docs/
    to be able to host them
    """
    cur_dir = os.getcwd()
    os.chdir(os.path.join(docs, 'html'))
    os.system("mv * ..")
    os.chdir(cur_dir)

def add_docs_dir_to_git():
    os.system(f"git add --all {docs}")

# delete old generated docs
delete_all_files(docs)
print(f"{'*'*20}  Deleted old docs {'*'*20} ")
regenrate_docs()
print(f"{'*'*20} Generated new docs {'*'*20} ")
# docs are generated in docs/html, move them to docs/ dir
move_html_files_to_docs_dir()
print(f"{'*'*20} Moved new docs from docs/html/ to docs/ dir {'*'*20} ")

add_docs_dir_to_git()
print(f"{'*'*20} Added new docs/ dir to git {'*'*20} ")





