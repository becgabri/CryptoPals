from copy import copy

# extremely expensive, returns list of lists with ALL
# permutation results
def perm(bag):
    words = []
    for idx in range(len(bag)):
        if idx == 0:
            for item in bag[idx]:
                words.append([item])
        else:
            tmp = []
            for current_item in words:
                for some_stuff in bag[idx]:
                    #modify_item = list(current_item)
                    current_item.append(some_stuff)
                    tmp.append(copy(current_item))
                    current_item.pop()
            words = tmp
    return words

# almost like a primitive decorator: takes a list of lists to
# permute and then a function to enact on each permuted result
# this is not as expensive as perm because it does NOT involve
# a copy but it's still expensive
def perm_function_res(bag, funct):
    words = []
    for idx in range(len(bag)):
        if idx == 0:
            for item in bag[idx]:
                words.append([item])
        else:
            tmp = []
            for current_item in words:
                for some_stuff in bag[idx]:
                    #modify_item = list(current_item)
                    current_item.append(some_stuff)
                    funct(current_item))
                    current_item.pop()

def main():
    print(perm([['a', 'b'], ['c', 'd']]))

if __name__ == "__main__":
    main()