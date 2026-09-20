import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from trace_m11_stillpath1a import branch,cstring,pair_value
class Tests(unittest.TestCase):
 def test_forward_bl(self): self.assertEqual(branch(0x1000,0xEB000002)['target'],0x1010)
 def test_backward_b(self): self.assertEqual(branch(0x1000,0xEAFFFFFE)['target'],0x1000)
 def test_blx_h0(self):
  self.assertEqual(branch(0x1000,0xFA000002)['target'],0x1010)
  self.assertEqual(branch(0x1000,0xFA000002)['state'],'Thumb')
 def test_blx_h1(self): self.assertEqual(branch(0x1000,0xFB000002)['target'],0x1012)
 def test_nonbranch(self): self.assertIsNone(branch(0x1000,0xE1A00000))
 def test_conditional(self):
  self.assertTrue(branch(0x1000,0x1A000002)['conditional'])
  self.assertFalse(branch(0x1000,0xEA000002)['conditional'])
 def test_known_iq_call(self): self.assertEqual(branch(0x17327E8,0xEBFFE9D4)['target'],0x172CF40)
 def test_known_beforetone_call(self): self.assertEqual(branch(0x172D3B0,0xEB10CBDA)['target'],0x1B60320)
 def test_newline(self): self.assertEqual(cstring(b'error\n\0',0),'error\n')
 def test_control_rejected(self): self.assertIsNone(cstring(b'error\x01\0',0))
 def test_rdma_pair(self): self.assertEqual(pair_value(0xE3063EB8,0xE34432B6),0x42B66EB8)
 def test_mismatched_pair(self): self.assertIsNone(pair_value(0xE3063EB8,0xE34422B6))
if __name__=='__main__': unittest.main()
