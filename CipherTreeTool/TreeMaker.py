import sys
import pandas as pd
from queue import Queue

from pre_generator import generate_dataset

MAX_SEC_LEVEL = 10

class Node:
    def __init__(self):
        self.left = -1
        self.right = -1
        self.type = None
        self.size = 0
        self.sec = 0
        self.lib = ""
        self.alg = ""
        self.key_len = 0
        self.mode = ""

    def __str__(self):
        _type = self.type
        if _type == None:
            _type = "none"

        arr = []
        arr.append("{" + str(self.left))
        arr.append(str(self.right))
        arr.append("\"" + _type + "\"")
        arr.append(str(self.size))
        arr.append(str(self.sec))
        arr.append("\"" + self.lib + "\"")
        arr.append("\"" + self.alg + "\"")
        arr.append(str(self.key_len))
        arr.append("\"" + self.mode + "\"" + "}")

        return ", ".join(arr)


class Tree:
    def __init__(self):
        self.left = None
        self.right = None
        self.data = None
        self.children = 0

    def __str__(self, level=0):
        ret = "\t"*level + repr(self) + "\n"
        if self.left != None:
            ret += self.left.__str__(level+1)
        if self.right != None:
            ret += self.right.__str__(level+1)
        return ret

    def __repr__(self):
        if self.data == None:
            return 'none'
        else:
            node = self.data
            if node.type == 'security':
                return "SEC - LESS OR EQ. THAN {:d} OR GREATER THAN {:d}".format(node.sec, node.sec)
            if node.type == 'size':
                return "SIZE - LESS OR EQ. THAN {:d} OR GREATER THAN {:d}".format(node.size, node.size)
            elif node.type == 'cipher':
                return "best: {}-{}-{} from {}".format(node.alg, node.key_len, node.mode, node.lib)

def createSecNode(level):
    node = Node()
    node.type = "security"
    node.sec = level
    return node

def createSizeNode(size):
    node = Node()
    node.type = "size"
    node.size = size
    return node

def buildBalancedTreeStructure(tree, df, field, create_node, start, end):
    if start > end and field == 'SEC_LEVEL':
        return buildBalancedTreeStructure(tree, df, 'FILE_BYTES', createSizeNode, 0, df['FILE_BYTES'].unique().shape[0] - 1)
    elif start > end:
        return 0

    middle = int((start + end) / 2)
    tree.data = create_node(df.sort_values(by=field)[field].unique()[middle])
    tree.right = Tree()
    tree.left = Tree()

    tree.children += buildBalancedTreeStructure(tree.left, df, field, create_node, start, middle - 1)
    tree.children += buildBalancedTreeStructure(tree.right, df, field, create_node, middle + 1, end)
    return tree.children + 1

def buildTree(tree, df):
    max_sec = df[df['SEC_LEVEL'] == df['SEC_LEVEL'].max()].index
    df_trunc = df.drop(max_sec, errors='raise')
    max_size = df_trunc[df_trunc['FILE_BYTES'] == df_trunc['FILE_BYTES'].max()].index
    df_trunc = df_trunc.drop(max_size, errors='raise')
    buildBalancedTreeStructure(tree, df_trunc, 'SEC_LEVEL', createSecNode, 0, df_trunc['SEC_LEVEL'].unique().shape[0] - 1)


def treePut(root, data):
    if root == None:
        return
    if root.data != None and root.data.type == "security":
        node = root.data
        if node.sec >= data['SEC_LEVEL']:
            treePut(root.left, data)
            return
        if node.sec < data['SEC_LEVEL']:
            treePut(root.right, data)
            return
    if root.data != None and root.data.type == "size":
        node = root.data
        if node.size >= data['FILE_BYTES']:
            treePut(root.left, data)
            return
        if node.size < data['FILE_BYTES']:
            treePut(root.right , data)
            return
    if root.data != None and root.data.type == "cipher":
        print("ERROR: data overlap at {}".format(data))
        exit()

    node = Node()
    node.type = "cipher"
    node.lib = data['LIB']
    node.alg = data['ALG']
    node.key_len = data['KEY_LEN']
    node.mode = data['BLOCK_MODE']
    root.data = node

def populateTree(root, tree_data):
    tree_data.apply(lambda row: treePut(root, row), axis=1)
    
def treeToCPP(tree, strarr):
    if tree == None:
        return -1

    _data = tree.data
    if _data == None:
        _data = Node()

    index = len(strarr)
    strarr.append(_data)
    left = treeToCPP(tree.left, strarr)
    if left > 0:
        _data.left = left
    right = treeToCPP(tree.right, strarr)
    if right > 0:
        _data.right = right
    return index

def generateCode(template, output, tree):
    fin = open(template, "rt")
    data = fin.read()
    fin.close()

    strarr = []
    treeToCPP(tree, strarr)
    strarr = [str(x) for x in strarr]
    str_tree_data = "\n\t, ".join(strarr)
    data = data.replace("%%tree_size%%", str(len(strarr)))
    data = data.replace("%%tree_data%%", str_tree_data)

    fout = open(output, "wt")
    fout.write(data)
    fout.close()

def main():
    benchmark_df = pd.read_csv(sys.argv[1])
    rounds_df = pd.read_csv(sys.argv[2])

    tree_df = generate_dataset(benchmark_df, rounds_df, MAX_SEC_LEVEL)

    root = Tree()
    buildTree(root, tree_df)
    populateTree(root, tree_df)
    tree_df.to_csv("tree.csv")
    generateCode(sys.argv[3], sys.argv[4], root)

if __name__ == "__main__":
    main()