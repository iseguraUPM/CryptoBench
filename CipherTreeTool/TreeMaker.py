import sys
import pandas as pd
from queue import Queue

class Node:
    def __init__(self):
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
        arr.append("{\"" + _type + "\"")
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

def getDummyData(file):
    tree_data = pd.read_csv(file)
    return tree_data

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
    
def treeToCPP(tree, index, strarr):
    if tree == None:
        return

    if index >= len(strarr):
        strarr.extend([str(Node())] * len(strarr))

    _data = tree.data
    if _data == None:
        _data = Node()

    strarr[index] = str(_data)
    treeToCPP(tree.left, 2 * index + 1, strarr)
    treeToCPP(tree.right, 2 * index + 2, strarr)

    return strarr

def generateCode(template, output, tree):
    fin = open(template, "rt")
    data = fin.read()
    fin.close()

    strarr = [str(Node())] * 16
    treeToCPP(tree, 0, strarr)
    str_tree_data = "\n\t, ".join(strarr)
    data = data.replace("%%tree_size%%", str(len(strarr)))
    data = data.replace("%%tree_data%%", str_tree_data)

    fout = open(output, "wt")
    fout.write(data)
    fout.close()

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

def main():
    tree_df = getDummyData(sys.argv[1])

    root = Tree()
    buildBalancedTreeStructure(root, tree_df, 'SEC_LEVEL', createSecNode, 0, tree_df['SEC_LEVEL'].unique().shape[0] - 1)
    populateTree(root, tree_df)
    generateCode(sys.argv[2], sys.argv[3], root)

if __name__ == "__main__":
    main()