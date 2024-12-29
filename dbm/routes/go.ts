import { Router } from 'express';
import { supabase } from "../lib";
import { PostgrestSingleResponse } from '@supabase/supabase-js';

export const router = Router()

router.get('/:companyId/:thirdPartyId', async (req, res) => {
    const result: PostgrestSingleResponse<never> = await supabase.from('vlans').insert({
        company_id: req.params.companyId,
        nas_id: req.params.thirdPartyId,
    }).select().single();

    if (result.error) {
        res.status(500).json(result.error);
        return
    }
    res.status(200).json(result.data);
})

router.delete('/:companyId/:thirdPartyId', async (req, res) => {
    const result: PostgrestSingleResponse<never> = await await supabase.from('vlans').delete().eq('nas_id', req.params.thirdPartyId).eq('company_id', req.params.companyId).select().single();
    if (result.error) {
        res.status(500).json(result.error);
        return
    }
    res.status(200).json(result.data);
})