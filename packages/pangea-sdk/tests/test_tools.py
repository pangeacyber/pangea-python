import unittest

from pangea.deep_verify import index2path, path2index


class TestRedact(unittest.TestCase):
    def setUp(self):
        pass

    def test_path_and_index(self):
        for tree_size in range(1, 1000):
            for leaf_index in range(0, tree_size - 1):
                path = index2path(tree_size, leaf_index)
                index = path2index(tree_size, path)
                self.assertEqual(leaf_index, index)
