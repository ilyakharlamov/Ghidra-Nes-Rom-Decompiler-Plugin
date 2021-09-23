#!/usr/bin/env python
import os
import re
import sys
import logging


class JavaSourceCode(object):
    def __init__(self, fpath):
        assert os.path.isfile(fpath), fpath


class Inliner(object):
    def __init__(self, class_resolve_dir_path):
        assert os.path.isdir(class_resolve_dir_path), class_resolve_dir_path
        self.__class_resolve_dir_path = class_resolve_dir_path

    def resolve_class_source_code(self, package_name):
        assert type(package_name) == str, package_name
        assert re.compile("([a-zA-Z_$][a-zA-Z\d_$]*\.)*[a-zA-Z_$][a-zA-Z\d_$]*").match(package_name), package_name
        subpath = package_name.replace(".", "/")
        class_fpath = os.path.join(self.__class_resolve_dir_path, subpath+".java")
        return self.resolve_class_source_code_fpath(class_fpath)

    def resolve_class_source_code_fpath(self, class_fpath):
        assert os.path.isfile(class_fpath), class_fpath
        precomments = []
        imports = []
        lines = []
        with open(class_fpath) as fin:
            for line in fin:
                if line.startswith("package"):
                    continue
                if line.startswith("import"):
                    imports.append(line)
                    continue
                if line.startswith("//") and not imports:
                    precomments.append(line)
                    continue
                lines.append(line)
        return (precomments, imports, lines)

    def import_to_java_fully_qualified_class_name(self, line):
        return line[line.find("import ")+len("import "):line.rfind(";")]

    def replacefile(self, fpath_from, fpath_to):
        already = set()
        with open(fpath_to, "w") as fout:
            (precomment_lines, import_lines, content_lines) = self.resolve_class_source_code_fpath(fpath_from)
            import_lines += ["import ik.ghidranesrom.wrappers.LoopWrapper;\n"]
            import_lines += ["import ik.ghidranesrom.wrappers.BrandedSymbolWrapper;\n"]
            import_lines += ["import ik.ghidranesrom.wrappers.InstructionWrapper;\n"]
            import_lines += ["import ik.ghidranesrom.wrappers.OperandObjectWrapper;\n"]
            for import_line in import_lines:
                if import_line.startswith("import ik.ghidranesrom") and import_line not in already:
                    (pre, imp, cont) = self.resolve_class_source_code(self.import_to_java_fully_qualified_class_name(import_line))
                    import_lines += imp
                    #import_lines += ["import ik.ghidranesrom.%s;" % re.compile("public class (\w+)\s*{").search(s).group(1) for s in cont if "public class" in cont]
                    content_lines += map(lambda line:line.replace("public class", "class").replace("public interface", "interface"), cont)
                    already.add(import_line)
            for precomment_line in precomment_lines:
                fout.write(precomment_line)
            for import_line in import_lines:
                if "import ik.ghidranesrom" in import_line:
                    continue
                fout.write(import_line)
            for content_line in content_lines:
                fout.write(content_line)


def find_src_dir():
    current_dir = os.path.dirname(__file__)
    while os.path.basename(current_dir) != "src":
        current_dir = os.path.dirname(current_dir)
        logging.info("current_dir: %s", current_dir)
    return current_dir


if __name__ == "__main__":
    script_src_dir = find_src_dir()
    script_source_dir = os.path.join(script_src_dir, "script", "java")
    script_resolve_dir = os.path.join(script_src_dir, "main", "java")
    script_target_dir = os.path.join(script_src_dir, "../", "ghidra_scripts", "src")
    assert os.path.isdir(script_target_dir), ("%s does not exist" % script_target_dir)
    for fname in os.listdir(script_source_dir):
        if not fname.endswith(".java"):
            continue
        fpath = os.path.join(script_source_dir, fname)
        target_fpath = os.path.join(script_target_dir, fname)
        inliner = Inliner(class_resolve_dir_path=script_resolve_dir)
        inliner.replacefile(fpath, target_fpath)
        print("file_written", target_fpath)
