from hashlib import sha256

class Node:
    """
    Tree node: left and right child + data which can be any object
    range = [min_val, max_val)
    """

    def __init__(self, data, min_val, max_val):
        """
        Node constructor

        @param data node data object
        """
        self.left = None
        self.right = None
        self.data = data
        self.max_val = max_val
        self.min_val = min_val

    def insert(self, data):
        """
        Insert new node with data

        @param data node data object to insert
        """
        if data < self.data:
            if self.left is None:
                self.left = Node(data)
            else:
                self.left.insert(data)
        else:
            if self.right is None:
                self.right = Node(data)
            else:
                self.right.insert(data)

    def lookup(self, data, parent=None):
        """
        Lookup node containing data

        @param data node data object to look up
        @param parent node's parent
        @returns node and node's parent if found or None, None
        """
        if data < self.data:
            if self.left is None:
                return None, None
            return self.left.lookup(data, self)
        elif data > self.data:
            if self.right is None:
                return None, None
            return self.right.lookup(data, self)
        else:
            return self, parent

    def lookup(self, val):
        return self.lookup_range(val, val+1).next()


    def generate_tree(self):
        if (self.max_val-1 > self.min_val):
            center = self.min_val + (self.max_val - self.min_val)/2
            # l_node = Node(str(self.min_val) + '-' + str(center), self.min_val, center)
            # r_node = Node(str(center) + '-' + str(self.max_val), center, self.max_val)
            l_node = Node(sha256(str(self.data) + 'l').hexdigest(), self.min_val, center)
            r_node = Node(sha256(str(self.data) + 'r').hexdigest(), center, self.max_val)
            # print str(self.data) + 'l', str(self.data) 
            self.left = l_node
            self.right = r_node
            for leaf_node in self.left.generate_tree():
                yield leaf_node
            for leaf_node in self.right.generate_tree():
                yield leaf_node
        else:
            yield self




    def lookup_range(self, min_val, max_val):

        if (min_val <= self.min_val and max_val >= self.max_val):
            yield self

        else:
            center = self.min_val + (self.max_val - self.min_val)/2

            l_max = min(max_val,center)
            if (l_max>min_val):
                for n in self.left.lookup_range(min_val, l_max):
                    yield n

            r_min = max(min_val,center)
            if (r_min<max_val):
                for n in self.right.lookup_range(r_min, max_val):
                    yield n

    def traverse_range(self, min_val, max_val):

        # center = min_val + (max_val-min_val)/2
        # leaves = iter()
        for i in self.lookup_range(min_val, max_val):
            for j in i.traverse_leaves():
                yield j


    def traverse_leaves(self):
        if self.right is None and self.left is None:
            yield self
        else:
            if self.right is not None:
                for i in self.right.traverse_leaves():
                    yield i
            if self.left is not None:
                for i in self.left.traverse_leaves():
                    yield i


        
    def generate_range(self, min_val, max_val):
        # print min_val, '-', max_val

        if (min_val <= self.min_val and max_val >= self.max_val):
            yield self

        else:
            center = self.min_val + (self.max_val - self.min_val)/2

            l_max = min(max_val,center)
            if (l_max > min_val):
                # l_node = Node(str(self.min_val) + '-' + str(center), self.min_val, center)
                # r_node = Node(str(center) + '-' + str(self.max_val), center, self.max_val)
                l_node = Node(sha256(str(self.data) + 'l').hexdigest(), self.min_val, center)
                # print "c", center
                self.left = l_node
                for n in self.left.generate_range(min_val, l_max):
                    yield n

            r_min = max(min_val,center)
            if (r_min<max_val):
                r_node = Node(sha256(str(self.data) + 'r').hexdigest(), center, self.max_val)
                # r_node = Node(str(center) + '-' + str(self.max_val), center, self.max_val)
                self.right = r_node
                for n in self.right.generate_range(r_min, max_val):
                    yield n



    def tree_data(self):
        """
        Generator to get the tree nodes data
        """
        # we use a stack to traverse the tree in a non-recursive way
        stack = []
        node = self
        while stack or node: 
            if node:
                stack.append(node)
                node = node.left
            else: # we are returning so we pop the node and we yield it
                node = stack.pop()
                yield node.data
                node = node.right

def main():
    hash_tree = Node(str(1)+ '-' + str(9), 1, 9)
    for n in hash_tree.generate_tree():
         x = n.min_val
    for n in hash_tree.traverse_range(2,8):
        print n.min_val

    # hash_tree = Node(str(1)+ '-' + str(9), 1, 9)
    # print hash_tree.tree_data()
    # for n in hash_tree.generate_tree():
    #     print n.data + ' '
    # for data in hash_tree.tree_data():
    #     print data + ' '

    # print "lookup"
    # for n in hash_tree.lookup_range(1,6):
    #     print n.min_val
    #     for i in n.traverse_leaves():
    #         print i.min_val
    # print hash_tree.lookup(5).data
    # hash_tree = Node(str(1)+ '-' + str(9), 1, 9)
    # for n in hash_tree.generate_range(2 ,7):
    #     print n.data
if __name__ == "__main__":
    main()
