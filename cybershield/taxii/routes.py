"""
TAXII 2.1 REST API Routes.
Exposes standard OASIS TAXII 2.1 endpoints for threat intelligence distribution and ingestion.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Response, status

from cybershield.taxii.schemas import (
    StixBundle,
    TaxiiApiRoot,
    TaxiiCollection,
    TaxiiCollectionsList,
    TaxiiEnvelope,
    TaxiiServerDiscovery,
    TaxiiStatusResponse,
    TAXII_MEDIA_TYPE_21,
)
from cybershield.taxii.server import TaxiiServerEngine

taxii_router = APIRouter(tags=["OASIS TAXII 2.1 Threat Intelligence"])
taxii_engine = TaxiiServerEngine()


@taxii_router.get("/taxii2/", response_model=TaxiiServerDiscovery)
async def taxii_discovery(response: Response):
    """TAXII 2.1 Server Discovery."""
    response.headers["Content-Type"] = TAXII_MEDIA_TYPE_21
    return taxii_engine.get_discovery()


@taxii_router.get("/taxii2/api/", response_model=TaxiiApiRoot)
async def taxii_api_root(response: Response):
    """TAXII 2.1 API Root."""
    response.headers["Content-Type"] = TAXII_MEDIA_TYPE_21
    return taxii_engine.get_api_root()


@taxii_router.get("/taxii2/api/collections/", response_model=TaxiiCollectionsList)
async def list_collections(response: Response):
    """List all available TAXII collections."""
    response.headers["Content-Type"] = TAXII_MEDIA_TYPE_21
    return taxii_engine.list_collections()


@taxii_router.get("/taxii2/api/collections/{collection_id}/", response_model=TaxiiCollection)
async def get_collection(collection_id: str, response: Response):
    """Retrieve details for a specific TAXII collection."""
    response.headers["Content-Type"] = TAXII_MEDIA_TYPE_21
    col = taxii_engine.get_collection(collection_id)
    if not col:
        raise HTTPException(status_code=404, detail=f"Collection '{collection_id}' not found")
    return col


@taxii_router.get("/taxii2/api/collections/{collection_id}/objects/", response_model=TaxiiEnvelope)
async def get_collection_objects(
    collection_id: str,
    response: Response,
    match_type: Optional[str] = Query(None, alias="match[type]"),
    match_id: Optional[str] = Query(None, alias="match[id]"),
    limit: int = Query(100, ge=1, le=500),
):
    """Query STIX 2.1 objects from a TAXII collection."""
    response.headers["Content-Type"] = TAXII_MEDIA_TYPE_21
    try:
        return taxii_engine.get_objects(
            collection_id=collection_id, match_type=match_type, match_id=match_id, limit=limit
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@taxii_router.post(
    "/taxii2/api/collections/{collection_id}/objects/",
    response_model=TaxiiStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def add_stix_bundle(collection_id: str, bundle: StixBundle, response: Response):
    """Ingest STIX 2.1 bundle into a TAXII collection."""
    response.headers["Content-Type"] = TAXII_MEDIA_TYPE_21
    try:
        return taxii_engine.add_objects_to_collection(collection_id, bundle.objects)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@taxii_router.get("/taxii2/api/status/{status_id}/", response_model=TaxiiStatusResponse)
async def get_status(status_id: str, response: Response):
    """Check status of an asynchronous TAXII ingestion request."""
    response.headers["Content-Type"] = TAXII_MEDIA_TYPE_21
    status_res = taxii_engine.get_status_job(status_id)
    if not status_res:
        raise HTTPException(status_code=404, detail=f"Status job '{status_id}' not found")
    return status_res
