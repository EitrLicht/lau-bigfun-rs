//! Virtual segment detection and volume geometry validation.

use super::{Bigfile, BigfileError};
use crate::fat::Entry;
use crate::format::{BLOCK_BYTE_COUNT, SECTOR_BYTE_COUNT, is_block_aligned};

impl Bigfile {
    /// Resolves `segment_length` and validates physical part boundaries and record bounds.
    pub(super) fn validate_volume_geometry(
        &mut self,
        segment_length_override: Option<u64>,
    ) -> Result<(), BigfileError> {
        self.segment_length = self.resolve_segment_length(segment_length_override)?;
        self.validate_part_starts()
            .and_then(|()| self.validate_records_fit())
            .map_err(|err| self.override_mismatch_or(segment_length_override, err))
    }

    /// Resolves the per-part logical segment stride: an explicit override as given once it is
    /// block-aligned, or else the logical offset of the first FAT record holding data past
    /// physical part 0 (picked by [`Self::first_spill_offset`]). Either way the part files and
    /// records must then fit it.
    ///
    /// Returns `Ok(None)` for unsplit single-part archives when no override is supplied.
    fn resolve_segment_length(
        &self,
        segment_length_override: Option<u64>,
    ) -> Result<Option<u64>, BigfileError> {
        if let Some(stride) = segment_length_override {
            Self::validate_segment_length(stride)?;
            return Ok(Some(stride));
        }
        if self.part_sizes.len() <= 1 {
            return Ok(None);
        }
        let detected_stride = Self::first_spill_offset(self.fat.entries(), self.part_sizes[0])
            .ok_or(BigfileError::UndeterminedSegmentLength {
                part_count: self.part_sizes.len(),
            })?;
        Self::validate_segment_length(detected_stride)?;
        Ok(Some(detected_stride))
    }

    /// Returns [`BigfileError::SegmentLengthMismatch`] in place of `err` when the archive did not
    /// fit an explicit override that differs from the stride its records show, and `err` itself
    /// otherwise.
    fn override_mismatch_or(
        &self,
        segment_length_override: Option<u64>,
        err: BigfileError,
    ) -> BigfileError {
        if let Some(override_length) = segment_length_override
            && self.part_sizes.len() > 1
            && let Some(detected_length) =
                Self::first_spill_offset(self.fat.entries(), self.part_sizes[0])
            && detected_length != override_length
        {
            return BigfileError::SegmentLengthMismatch {
                override_length,
                detected_length,
            };
        }
        err
    }

    /// Finds the smallest logical byte offset among entries that hold data and start at or beyond
    /// physical part 0's end. That is the start of part 1, so the segment length, whenever part 1
    /// begins with a record that holds data. No record with data can start in the gap between
    /// part 0's end and part 1, but an empty one can sit exactly at part 0's end, so empty entries
    /// are skipped.
    fn first_spill_offset(entries: &[Entry], part0_size: u64) -> Option<u64> {
        entries
            .iter()
            .filter(|entry| entry.stored_size() > 0)
            .map(Entry::logical_offset)
            .filter(|&logical| logical >= part0_size)
            .min()
    }

    /// Validates that `segment_length` is positive and 1 MiB block-aligned.
    fn validate_segment_length(segment_length: u64) -> Result<(), BigfileError> {
        if segment_length == 0 || !is_block_aligned(segment_length) {
            return Err(BigfileError::UnalignedSegmentLength {
                segment_length,
                block_size: BLOCK_BYTE_COUNT,
            });
        }
        Ok(())
    }

    /// Validates that every record's physical bytes lie after the FAT header and wholly within
    /// a single physical part file.
    fn validate_records_fit(&self) -> Result<(), BigfileError> {
        let fat_byte_size = self.fat.header_byte_size() as u64;
        for entry in self.fat.entries() {
            self.validate_single_record_fit(entry, fat_byte_size)?;
        }
        Ok(())
    }

    /// Validates physical bounds for a single [`Entry`].
    fn validate_single_record_fit(
        &self,
        entry: &Entry,
        fat_byte_size: u64,
    ) -> Result<(), BigfileError> {
        let need = entry.stored_size();
        let logical_offset = entry.logical_offset();
        if need > 0 && logical_offset < fat_byte_size {
            return Err(BigfileError::RecordOverlapsFat {
                index: entry.index,
                name_hash: entry.name_hash,
                sector_number: entry.sector_number,
                logical_offset,
                fat_byte_size,
            });
        }

        self.locate_validated_coords(entry)?;
        Ok(())
    }

    /// Validates that no physical part exceeds `segment_length` and every part `k >= 1` begins at
    /// offset 0 with some entry's data.
    fn validate_part_starts(&self) -> Result<(), BigfileError> {
        self.validate_parts_within_segment_length()?;
        match self.segment_length {
            Some(segment_length) if self.part_sizes.len() > 1 => {
                self.validate_multipart_start_sectors(segment_length)
            }
            _ => Ok(()),
        }
    }

    /// Validates that no physical part file exceeds `segment_length` when a segment stride is set.
    fn validate_parts_within_segment_length(&self) -> Result<(), BigfileError> {
        if let Some(segment_length) = self.segment_length {
            for (k, &physical_size) in self.part_sizes.iter().enumerate() {
                if physical_size > segment_length {
                    return Err(BigfileError::PartExceedsSegmentLength {
                        part_index: k,
                        part_path: self.part_paths[k].clone(),
                        physical_size,
                        segment_length,
                    });
                }
            }
        }
        Ok(())
    }

    /// Validates that every part `k >= 1` of a multi-part archive split every `segment_length`
    /// bytes has at least one entry starting at its offset 0.
    fn validate_multipart_start_sectors(&self, segment_length: u64) -> Result<(), BigfileError> {
        let mut has_part_start = vec![false; self.part_sizes.len()];
        for entry in self.fat.entries() {
            if let Ok((part_index, 0)) = self.locate_coords(entry) {
                has_part_start[part_index] = true;
            }
        }
        let sectors_per_segment = segment_length / u64::from(SECTOR_BYTE_COUNT);

        for (k, &started) in has_part_start.iter().enumerate().skip(1) {
            if !started {
                let expected_sector = (k as u64).saturating_mul(sectors_per_segment);
                return Err(BigfileError::MissingPartStartEntry {
                    part_index: k,
                    part_path: self.part_paths[k].clone(),
                    expected_sector,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::sector_logical_offset;
    use crate::test_support::sample_entry;

    /// Part 0 size used by the tests below: 10 sectors.
    const PART0_SIZE: u64 = (SECTOR_BYTE_COUNT * 10) as u64;

    #[test]
    fn first_spill_offset_is_the_smallest_offset_past_part0() {
        let entries = [
            sample_entry(0, 1, 1, 1),
            sample_entry(1, 2, 512, 1),
            sample_entry(2, 3, 12, 1),
        ];
        assert_eq!(
            Bigfile::first_spill_offset(&entries, PART0_SIZE),
            Some(sector_logical_offset(12))
        );
    }

    #[test]
    fn first_spill_offset_skips_empty_records() {
        let empty_at_part0_end = Entry {
            size: 0,
            ..sample_entry(0, 1, 10, 1)
        };
        let entries = [empty_at_part0_end, sample_entry(1, 2, 512, 1)];
        assert_eq!(
            Bigfile::first_spill_offset(&entries, PART0_SIZE),
            Some(sector_logical_offset(512))
        );
    }
}
