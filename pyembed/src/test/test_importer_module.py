# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import unittest

SYMBOL_ATTRIBUTES = {
    "OxidizedDistribution": {
        "discover",
        "entry_points",
        "files",
        "from_name",
        "metadata",
        "read_text",
        "requires",
        "version",
    },
    "OxidizedFinder": {
        "add_resource",
        "add_resources",
        "create_module",
        "exec_module",
        "find_distributions",
        "find_module",
        "find_spec",
        "get_code",
        "get_data",
        "get_filename",
        "get_resource_reader",
        "get_source",
        "index_bytes",
        "index_file_memory_mapped",
        "index_interpreter_builtins",
        "index_interpreter_builtin_extension_modules",
        "index_interpreter_frozen_modules",
        "indexed_resources",
        "invalidate_caches",
        "iter_modules",
        "multiprocessing_set_start_method",
        "origin",
        "path_hook",
        "path_hook_base_str",
        "pkg_resources_import_auto_register",
        "serialize_indexed_resources",
    },
    "OxidizedPathEntryFinder": {
        "_package",
        "find_spec",
        "invalidate_caches",
        "iter_modules",
    },
    "OxidizedPkgResourcesProvider": {
        "get_metadata",
        "get_metadata_lines",
        "get_resource_filename",
        "get_resource_string",
        "get_resource_stream",
        "has_metadata",
        "has_resource",
        "metadata_isdir",
        "metadata_listdir",
        "resource_isdir",
        "resource_listdir",
        "run_script",
    },
    "OxidizedResource": {
        "in_memory_bytecode_opt1",
        "in_memory_bytecode_opt2",
        "in_memory_bytecode",
        "in_memory_distribution_resources",
        "in_memory_extension_module_shared_library",
        "in_memory_package_resources",
        "in_memory_shared_library",
        "in_memory_source",
        "is_builtin_extension_module",
        "is_extension_module",
        "is_frozen_module",
        "is_module",
        "is_namespace_package",
        "is_package",
        "is_shared_library",
        "name",
        "relative_path_distribution_resources",
        "relative_path_extension_module_shared_library",
        "relative_path_module_bytecode_opt1",
        "relative_path_module_bytecode_opt2",
        "relative_path_module_bytecode",
        "relative_path_module_source",
        "relative_path_package_resources",
        "shared_library_dependency_names",
    },
    "OxidizedResourceCollector": {
        "add_filesystem_relative",
        "add_in_memory",
        "allowed_locations",
        "oxidize",
    },
    "OxidizedResourceReader": {
        "contents",
        "is_resource",
        "open_resource",
        "resource_path",
    },
    "PythonExtensionModule": {"name"},
    "PythonModuleBytecode": {
        "bytecode",
        "is_package",
        "module",
        "optimize_level",
    },
    "PythonModuleSource": {"is_package", "module", "source"},
    "PythonPackageDistributionResource": {"data", "name", "package", "version"},
    "PythonPackageResource": {"data", "name", "package"},
}


class TestImporterModule(unittest.TestCase):
    def test_module(self):
        import oxidized_importer as importer

        attrs = {a for a in dir(importer) if not a.startswith("__")}
        self.assertEqual(
            attrs,
            {
                "decode_source",
                "find_resources_in_path",
                "pkg_resources_find_distributions",
                "register_pkg_resources",
                "OxidizedDistribution",
                "OxidizedFinder",
                "OxidizedPathEntryFinder",
                "OxidizedPkgResourcesProvider",
                "OxidizedResourceCollector",
                "OxidizedResourceReader",
                "OxidizedResource",
                "PythonExtensionModule",
                "PythonModuleBytecode",
                "PythonModuleSource",
                "PythonPackageDistributionResource",
                "PythonPackageResource",
            },
        )

    def test_symbol_attrs(self):
        import oxidized_importer as importer

        for (symbol, expected) in sorted(SYMBOL_ATTRIBUTES.items()):
            o = getattr(importer, symbol)
            attrs = {a for a in dir(o) if not a.startswith("__")}
            self.assertEqual(attrs, expected, "attributes on %s" % symbol)


if __name__ == "__main__":
    unittest.main()
