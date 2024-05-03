use crate::{
    AggregateWithHashExtractionKey, AggregateWithHashPublicParams,
    AssignedAggregateWithHashExtractionKey, AssignedAggregateWithHashPartialKeys,
    AssignedAggregateWithHashPublicParams,
};
use ff::PrimeField;
use halo2wrong::halo2::plonk::Error;
use maingate::RegionCtx;

/// Instructions for AggregateWithHash operations.
pub trait AggregateWithHashInstructions<F: PrimeField> {
    /// Assigns a [`AssignedAggregateWithHashPublicParams`].
    fn assign_public_params(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_params: AggregateWithHashPublicParams<F>,
    ) -> Result<AssignedAggregateWithHashPublicParams<F>, Error>;

    /// Assigns a [`AssignedAggregateWithHashExtractionKey`].
    fn assign_extraction_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        extraction_key: AggregateWithHashExtractionKey<F>,
    ) -> Result<AssignedAggregateWithHashExtractionKey<F>, Error>;

    /// Given partial keys `Vec<(u,v,y,w)>`, a AggregateWithHash extraction key (u,v,y,w), performs the modular multiplication repeatedly.
    fn aggregate_with_hash(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        partial_keys: &AssignedAggregateWithHashPartialKeys<F>,
        public_params: &AssignedAggregateWithHashPublicParams<F>,
    ) -> Result<AssignedAggregateWithHashExtractionKey<F>, Error>;
}