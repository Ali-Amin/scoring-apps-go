package dcf_scoring

import data.classes
import input.class

has_key(x, k) { _ = x[k] }

weights[w] {
    has_key(classes,class)
    w:=classes[class]["weights"]
}

weights[w] {
    not has_key(classes,class)
    w:=classes["default"]["weights"]
}

attestation_opts[opts] {
    has_key(classes,class)
    opts:=classes[class]["attestationOpts"]
}

attestation_opts[opts] {
    not has_key(classes,class)
    opts:=classes["default"]["attestationOpts"]
}