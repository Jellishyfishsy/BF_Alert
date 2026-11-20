"""Nap 3 mo hinh, xep hang chung va du doan dong thoi tren cung mot luong."""

import warnings
from typing import NamedTuple

import joblib
import pandas as pd
from sklearn.exceptions import InconsistentVersionWarning

from detector.config import (
    BENIGN_LABEL,
    LABEL_ENCODER_FILE,
    MODELS_DIR,
    RANKING_FILE,
    model_key,
    sort_ranking,
)
from detector.features import check_feature_names


class ModelResult(NamedTuple):
    """Ket qua cua mot mo hinh tren mot luong."""

    name: str
    label: str
    conf: float
    attack_prob: float
    is_primary: bool


def _col(name, field):
    """Ten cot ket qua, vd. ("Random Forest", "label") -> "random_forest_label"."""
    return f"{model_key(name)}_{field}"


class EnsemblePredictor:
    """Ba mo hinh du doan cung luc. Mo hinh dau tien (primary) quyet dinh canh bao."""

    def __init__(self, primary=None):
        # Bang xep hang duoc buoc 04 ghi cung luc voi cac file model.
        # Xep theo RANKING_COLUMNS (Recall_Attack roi F1_Macro); bang cu chi co F1_Macro.
        xep_hang = sort_ranking(pd.read_csv(RANKING_FILE))
        self.f1 = dict(zip(xep_hang["Mo hinh"], xep_hang["F1_Macro"]))
        self.recall_attack = dict(zip(
            xep_hang["Mo hinh"],
            xep_hang["Recall_Attack"] if "Recall_Attack" in xep_hang else [float("nan")] * len(xep_hang),
        ))
        self.order = list(self.f1)
        if primary is not None:
            self.order.remove(primary)
            self.order.insert(0, primary)

        self.encoder = joblib.load(LABEL_ENCODER_FILE)
        self.classes = list(self.encoder.classes_)
        self.benign_index = self.classes.index(BENIGN_LABEL)

        with warnings.catch_warnings():
            # Model phai duoc nap bang dung phien ban scikit-learn da luu (requirements.txt):
            # luon hien canh bao nay, ke ca khi chay voi -W ignore
            warnings.simplefilter("always", InconsistentVersionWarning)
            self.models = {name: joblib.load(MODELS_DIR / f"{model_key(name)}.joblib")
                           for name in self.order}

        # str(): feature_names_in_ chua numpy.str_, sklearn khong coi do la ten cot
        # nen bo qua buoc kiem tra ten cot cua X ("X does not have valid feature names")
        self.feature_names = [str(n) for n in self.models[self.primary].feature_names_in_]
        for name, model in self.models.items():
            if list(model.feature_names_in_) != self.feature_names:
                raise ValueError(f"Mo hinh {name} dung bo dac trung khac cac mo hinh con lai")
        check_feature_names(self.feature_names)

    @property
    def primary(self) -> str:
        return self.order[0]

    def score_text(self, name, ascii_only=False) -> str:
        """Chi so xep hang cua mot mo hinh, vd. "Recall tấn công 0.9990 · F1-macro 0.9995".
        ascii_only=True cho man hinh console (khong dau)."""
        nhan, noi = ("Recall tan cong", " | ") if ascii_only else ("Recall tấn công", " · ")
        recall = self.recall_attack.get(name, float("nan"))
        phan = [] if pd.isna(recall) else [f"{nhan} {recall:.4f}"]
        return noi.join(phan + [f"F1-macro {self.f1[name]:.4f}"])

    def predict(self, X: pd.DataFrame) -> pd.DataFrame:
        """Tra ve bang ket qua: <key>_label, <key>_conf, <key>_attack_prob cho moi mo hinh,
        cung voi primary_label va is_attack (theo mo hinh chinh)."""
        X = X[self.feature_names]
        out = pd.DataFrame(index=X.index)

        for name in self.order:
            proba = self.models[name].predict_proba(X)
            out[_col(name, "label")] = [self.classes[i] for i in proba.argmax(axis=1)]
            out[_col(name, "conf")] = proba.max(axis=1)
            out[_col(name, "attack_prob")] = 1.0 - proba[:, self.benign_index]

        labels = self.labels(out)
        out["primary_model"] = self.primary
        out["primary_label"] = labels[self.primary]
        out["is_attack"] = out["primary_label"] != BENIGN_LABEL
        out["so_mo_hinh_bao_tan_cong"] = (labels != BENIGN_LABEL).sum(axis=1)
        return out

    def labels(self, res: pd.DataFrame) -> pd.DataFrame:
        """Nhan du doan cua tung mo hinh: moi cot la mot mo hinh, theo thu tu xep hang."""
        return pd.DataFrame({name: res[_col(name, "label")] for name in self.order})

    def results(self, row) -> list[ModelResult]:
        """Ket qua cua tung mo hinh tren mot hang cua bang predict(), mo hinh chinh dau tien."""
        return [
            ModelResult(name, row[_col(name, "label")], row[_col(name, "conf")],
                        row[_col(name, "attack_prob")], name == self.primary)
            for name in self.order
        ]
