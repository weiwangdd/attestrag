import pytest

from attestrag.attest import CompositeAttester, CompositeVerifier, Platform
from attestrag.attest.mock import MockAttester, MockTEEConfig, MockVendor, MockVerifier
from attestrag.policy import Policy

GOOD_MEASUREMENT = "ab" * 48
GPU_MEASUREMENT = "cd" * 48


@pytest.fixture
def vendors():
    return MockVendor("mock-amd"), MockVendor("mock-nvidia")


@pytest.fixture
def verifier(vendors):
    cpu_v, gpu_v = vendors
    mv = MockVerifier({cpu_v.name: cpu_v.root_public, gpu_v.name: gpu_v.root_public})
    return CompositeVerifier({Platform.MOCK_CPU: mv, Platform.MOCK_GPU: mv})


@pytest.fixture
def make_attester(vendors):
    cpu_v, gpu_v = vendors

    def _make(measurement=GOOD_MEASUREMENT, tcb=None, debug=False, gpus=0, gpu_tcb=None):
        cfg = MockTEEConfig(measurement=measurement, debug=debug)
        if tcb is not None:
            cfg.tcb = tcb
        gpu_cfg = MockTEEConfig(Platform.MOCK_GPU, GPU_MEASUREMENT, gpu_tcb or {"vbios": 96, "driver": 550})
        return CompositeAttester(
            MockAttester(cpu_v, cfg), [MockAttester(gpu_v, gpu_cfg) for _ in range(gpus)]
        )

    return _make


@pytest.fixture
def policy():
    return Policy(
        allowed_cpu_platforms=frozenset({Platform.MOCK_CPU}),
        allowed_measurements=frozenset({GOOD_MEASUREMENT}),
        min_tcb={"bootloader": 3, "snp": 8, "microcode": 115},
        allowed_gpu_platforms=frozenset({Platform.MOCK_GPU}),
        min_gpu_tcb={"driver": 535},
    )
