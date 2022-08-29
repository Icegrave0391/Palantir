from claripy import Annotation
from angr.knowledge_plugins.key_definitions.tag import FunctionTag


class TaintTag(FunctionTag):
    """
    Taint tag
    """
    def __init__(self, function=None, metadata=None):
        super(TaintTag, self).__init__(function=function, metadata=metadata)

        # sanity check
        if self.metadata["tagged_tp"] == "symbol" and\
                not isinstance(self.metadata["tagged_off"], str):
            raise TypeError()

    @staticmethod
    def from_other(other: 'TaintTag'):
        tagged_by = other.metadata["tagged_by"]
        tagged_tp = other.metadata["tagged_tp"]
        tagged_off = other.metadata["tagged_off"]
        tagged_sz = other.metadata["tagged_sz"]
        return TaintTag(function=other.function, metadata={
            "tagged_by": tagged_by, "tagged_tp": tagged_tp,
            "tagged_off": tagged_off, "tagged_sz": tagged_sz,
        })

    def __hash__(self):
        assert isinstance(self.metadata, dict)
        assert "tagged_tp" in self.metadata.keys() and \
               "tagged_sz" in self.metadata.keys() and \
               "tagged_off" in self.metadata.keys()

        val = (self.metadata["tagged_tp"], self.metadata["tagged_off"], self.metadata["tagged_sz"])
        return hash(val)

    def __eq__(self, other):
        if not isinstance(other, TaintTag):
            return False
        return self.metadata["tagged_tp"] == other.metadata["tagged_tp"] and \
               self.metadata["tagged_off"] == other.metadata["tagged_off"] and \
               self.metadata["tagged_sz"] == other.metadata["tagged_sz"]

    def __repr__(self):
        return f"<TaintTag type: {self.metadata['tagged_tp']}, offset: {self.metadata['tagged_off']}, " \
               f"size: {self.metadata['tagged_sz']}>"


class TaintTagAnnotation(Annotation):
    __slots__ = ('taint_tags',)

    def __init__(self, tags):
        super().__init__()
        self.taint_tags = tags if tags is not None else set()

    @property
    def relocatable(self):
        return True

    @property
    def eliminatable(self):
        return False

    def __hash__(self):
        hashed = 0
        for tag in self.taint_tags:
            hashed += hash(tag)
        return hash((hashed, self.relocatable, self.eliminatable))

    def __eq__(self, other: 'TaintTagAnnotation'):
        if not isinstance(other, TaintTagAnnotation):
            return False
        return self.taint_tags == other.taint_tags \
               and self.relocatable == other.relocatable \
               and self.eliminatable == other.eliminatable

    def __repr__(self):
        return f"<TaintTagAnno {self.taint_tags}>"