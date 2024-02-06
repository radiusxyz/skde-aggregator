use crate::{
    AggregateExtractionKey, AggregatePublicParams, AssignedAggregatePartialKeys,
    AssignedAggregatePublicParams, AssignedExtractionKey,
};
use ff::PrimeField;
use halo2wrong::halo2::plonk::Error;
use maingate::RegionCtx;

/// Instructions for Aggregate operations.
pub trait AggregateInstructions<F: PrimeField> {
    /// Assigns a [`AssignedAggregatePublicParams`].
    fn assign_public_params(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_params: AggregatePublicParams<F>,
    ) -> Result<AssignedAggregatePublicParams<F>, Error>;

    /// Assigns a [`AssignedExtractionKey`].
    fn assign_extraction_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        extraction_key: AggregateExtractionKey<F>,
    ) -> Result<AssignedExtractionKey<F>, Error>;

    /// Given a base `x`, a Aggregate public key (e,n), performs the modular power `x^e mod n`.
    fn aggregate(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        partial_keys: &AssignedAggregatePartialKeys<F>,
        public_params: &AssignedAggregatePublicParams<F>,
    ) -> Result<AssignedExtractionKey<F>, Error>;
}
