from prototypes.class_groups.cl import new_cl_class
from prototypes.class_groups.group import element_order, AbelianGroup

if __name__ == "__main__":
    Group = new_cl_class(-4643654683)
    assert issubclass(Group, AbelianGroup)
    """
        sage: group = BQFClassGroup(-4643654683)
    """

    elem = Group(33821, -16349, 36301)
    assert isinstance(elem, AbelianGroup)
    assert element_order(elem) == 3135
    """
        sage: elem = group(BinaryQF(33821, -16349, 36301))
        sage: elem.order()
        3135
    """

    y = elem * 4873
    assert y == Group(2099, 605, 553123)
    """
        sage: y = elem * 4873; y
        Class of 2099*x^2 + 605*x*y + 553123*y^2
    """

    assert Group.zero() == Group(1, 1, 1160913671)
    """
        sage: group.zero()
        Class of x^2 + x*y + 1160913671*y^2
    """

    z = elem + y
    assert z == Group(21923, 21401, 58177)
    """
        sage: z = elem + y; z
        Class of 21923*x^2 + 21401*x*y + 58177*y^2
    """
